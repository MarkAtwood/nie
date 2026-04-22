//! Integration test: `nie-bot --self-test` end-to-end.
//!
//! Starts an in-process relay on a random port, writes a temporary identity
//! keyfile, then runs the `nie-bot` binary with `--self-test` and asserts it
//! exits 0 within 8 seconds.
//!
//! To run this test manually:
//!   cargo test -p nie-bot --test self_test -- --nocapture

use axum::{routing::get, Router};
use nie_core::{identity::Identity, keyfile::encrypt_keyfile};
use nie_relay::{state::AppState, ws::ws_handler};

/// Start an in-process relay on a random OS-assigned port.
/// Returns the WebSocket URL.  Each call gets its own temp SQLite file so
/// parallel test runs never collide.
async fn spawn_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_url = format!("sqlite:{}?mode=rwc", db_file.path().display());

    let state = AppState::new(&db_url, 60, false, 1_000_000, 30, 120)
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

#[tokio::test]
async fn self_test_exits_zero() {
    let relay_url = spawn_relay().await;

    // Generate a fresh identity and write it as an age-encrypted keyfile
    // with an empty passphrase (--no-passphrase path).
    let identity = Identity::generate();
    let seed = identity.to_secret_bytes_64();
    let ciphertext = encrypt_keyfile(&seed, "").expect("encrypt_keyfile failed");

    let keyfile = tempfile::NamedTempFile::new().expect("temp keyfile");
    std::fs::write(keyfile.path(), &ciphertext).expect("write keyfile");

    let bin = env!("CARGO_BIN_EXE_nie-bot");
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        tokio::process::Command::new(bin)
            .arg("--self-test")
            .arg("--relay")
            .arg(&relay_url)
            .arg("--keyfile")
            .arg(keyfile.path())
            .arg("--no-passphrase")
            .status(),
    )
    .await
    .expect("nie-bot --self-test timed out after 8s")
    .expect("nie-bot process failed to start");

    assert!(
        status.success(),
        "nie-bot --self-test exited with non-zero status: {status}"
    );
}
