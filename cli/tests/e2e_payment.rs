//! CLI end-to-end payment integration test (nie-f91).
//!
//! Spins up an in-process relay, initializes Alice (pre-loaded testnet wallet)
//! and Bob (fresh wallet), has Alice pay Bob 0.001 TAZ, and asserts Bob
//! receives a PaymentAction::Confirmed notification within 120 seconds.
//!
//! # Required environment variables
//!
//! ```text
//! TESTNET_ENABLED=1     — opt-in guard; test is skipped if absent
//! ALICE_MNEMONIC="..."  — 24-word BIP-39 mnemonic for Alice's funded wallet
//! ALICE_PRELOADED_DB=/path — SQLite wallet.db with scanned notes and witnesses
//! ```
//!
//! # Optional
//!
//! ```text
//! TESTNET_ENDPOINT=https://... — override default lightwalletd URL
//! ZCASH_PARAMS=/path           — Sapling params dir (default: ~/.zcash-params)
//! ```
//!
//! # Running
//!
//! ```sh
//! TESTNET_ENABLED=1 \
//!   ALICE_MNEMONIC="word1 word2 ..." \
//!   ALICE_PRELOADED_DB=/path/to/alice-funded.db \
//!   ZCASH_PARAMS=$HOME/.zcash-params \
//!   cargo test --test e2e_payment -- --ignored --nocapture
//! ```

use axum::{routing::get, Router};
use nie_relay::{state::AppState, ws::ws_handler};
use std::time::Duration;
use tempfile::TempDir;

const PAYMENT_AMOUNT_ZEC: &str = "0.001";
const CONFIRM_TIMEOUT_SECS: u64 = 120;
const DEFAULT_TESTNET_ENDPOINT: &str = "https://lightwalletd.testnet.z.cash:443";

fn testnet_enabled() -> bool {
    std::env::var("TESTNET_ENABLED").as_deref() == Ok("1")
}

/// Start an in-process relay on a random OS-assigned port. Returns the WebSocket URL.
async fn spawn_relay() -> (String, TempDir) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay listener");
    let port = listener.local_addr().unwrap().port();

    let db_dir = TempDir::new().expect("relay temp dir");
    let db_url = format!(
        "sqlite:{}?mode=rwc",
        db_dir.path().join("relay.db").display()
    );

    let state = AppState::new(&db_url, 60, false, 1_000_000, 30)
        .await
        .expect("create AppState");
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("relay serve");
    });

    // Brief pause so the relay is ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    (format!("ws://127.0.0.1:{port}/ws"), db_dir)
}

/// Run a nie CLI command as a subprocess with --no-passphrase.
/// Returns stdout as a String. Panics if the command fails.
fn run_nie(data_dir: &std::path::Path, args: &[&str]) -> String {
    let nie_bin = env!("CARGO_BIN_EXE_nie");
    let output = std::process::Command::new(nie_bin)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--no-passphrase")
        .args(args)
        .output()
        .expect("nie subprocess failed to start");
    if !output.status.success() {
        panic!(
            "nie {:?} exited {:?}\nstdout: {}\nstderr: {}",
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn cli_testnet_payment_end_to_end() {
    if !testnet_enabled() {
        eprintln!("TESTNET_ENABLED not set — skipping CLI payment integration test");
        return;
    }

    let alice_db_path = std::env::var("ALICE_PRELOADED_DB").expect(
        "ALICE_PRELOADED_DB must be set (path to a wallet.db with scanned notes and witnesses)",
    );
    let alice_mnemonic = std::env::var("ALICE_MNEMONIC")
        .expect("ALICE_MNEMONIC must be set when ALICE_PRELOADED_DB is set");

    let testnet_endpoint =
        std::env::var("TESTNET_ENDPOINT").unwrap_or_else(|_| DEFAULT_TESTNET_ENDPOINT.to_string());

    // --- Start in-process relay ---
    let (relay_url, _relay_db_dir) = spawn_relay().await;
    eprintln!("relay started at {relay_url}");

    // --- Bob: fresh identity + fresh wallet ---
    let bob_dir = TempDir::new().expect("bob temp dir");
    run_nie(bob_dir.path(), &["init"]);
    run_nie(bob_dir.path(), &["wallet", "init"]);
    let bob_pubid = run_nie(bob_dir.path(), &["whoami"]).trim().to_string();
    eprintln!("bob pubid: {bob_pubid}");
    assert_eq!(
        bob_pubid.len(),
        64,
        "pubid must be 64 hex chars, got: {bob_pubid:?}"
    );

    // --- Alice: fresh identity + restore wallet from mnemonic ---
    let alice_dir = TempDir::new().expect("alice temp dir");
    run_nie(alice_dir.path(), &["init"]);

    // wallet_restore reads the mnemonic via rustyline, which falls back to
    // line-buffered stdin when not connected to a tty. Pipe the mnemonic phrase.
    {
        let nie_bin = env!("CARGO_BIN_EXE_nie");
        let mut child = std::process::Command::new(nie_bin)
            .arg("--data-dir")
            .arg(alice_dir.path())
            .arg("--no-passphrase")
            .arg("wallet")
            .arg("restore")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn nie wallet restore");

        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin pipe")
            .write_all(format!("{alice_mnemonic}\n").as_bytes())
            .expect("write mnemonic");

        let output = child.wait_with_output().expect("wait for wallet restore");
        if !output.status.success() {
            panic!(
                "wallet restore failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Copy Alice's pre-loaded wallet.db over the freshly restored one so Alice
    // has spendable notes and Merkle witnesses ready without rescanning.
    std::fs::copy(&alice_db_path, alice_dir.path().join("wallet.db"))
        .expect("copy ALICE_PRELOADED_DB");
    eprintln!("alice wallet DB: {alice_db_path}");

    let nie_bin = env!("CARGO_BIN_EXE_nie");

    // --- Start Bob chat subprocess ---
    let mut bob_proc = tokio::process::Command::new(nie_bin)
        .arg("--data-dir")
        .arg(bob_dir.path())
        .arg("--no-passphrase")
        .arg("--relay")
        .arg(&relay_url)
        .arg("--network")
        .arg("testnet")
        .arg("--lightwalletd")
        .arg(&testnet_endpoint)
        .arg("chat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn bob nie chat");

    // --- Start Alice chat subprocess ---
    let mut alice_proc = tokio::process::Command::new(nie_bin)
        .arg("--data-dir")
        .arg(alice_dir.path())
        .arg("--no-passphrase")
        .arg("--relay")
        .arg(&relay_url)
        .arg("--network")
        .arg("testnet")
        .arg("--lightwalletd")
        .arg(&testnet_endpoint)
        .arg("chat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn alice nie chat");

    // Give both clients time to authenticate and appear in the relay's directory.
    // 5 s is generous for loopback; MLS setup may add 1-2 s on slow machines.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // --- Alice pays Bob ---
    use tokio::io::AsyncWriteExt;
    let alice_stdin = alice_proc.stdin.as_mut().expect("alice stdin");
    let pay_cmd = format!("/pay {bob_pubid} {PAYMENT_AMOUNT_ZEC}\n");
    eprintln!("alice sending: {pay_cmd:?}");
    alice_stdin
        .write_all(pay_cmd.as_bytes())
        .await
        .expect("write pay command to alice stdin");

    // --- Watch Bob's stdout for confirmation ---
    use tokio::io::{AsyncBufReadExt, BufReader};
    let bob_stdout = bob_proc.stdout.take().expect("bob stdout");
    let mut bob_lines = BufReader::new(bob_stdout).lines();

    let confirmed = tokio::time::timeout(Duration::from_secs(CONFIRM_TIMEOUT_SECS), async {
        while let Ok(Some(line)) = bob_lines.next_line().await {
            eprintln!("[bob] {line}");
            if line.contains("[pay] Payment confirmed on-chain") {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    // Kill subprocesses.
    let _ = alice_proc.kill().await;
    let _ = bob_proc.kill().await;

    assert!(
        confirmed,
        "Bob did not receive PaymentAction::Confirmed within {CONFIRM_TIMEOUT_SECS}s. \
         Check testnet lightwalletd connectivity and Alice's wallet balance."
    );
    eprintln!("PASS: end-to-end testnet payment confirmed");
}
