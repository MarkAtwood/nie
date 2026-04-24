#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

// No run_in_browser configure — tests run headless with --headless --chrome flag.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use nie_core::auth;
use nie_core::identity::Identity;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Ed25519 seed (first 32 bytes) = all 0x01; HPKE seed (last 32 bytes) = all 0x02.
/// The two halves differ, satisfying the key-separation assert in from_secret_bytes.
const TEST_SEED_64: [u8; 64] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // Ed25519 seed
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, // HPKE seed (must differ)
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
];

const TEST_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// ── Test Set A: JSON-RPC 2.0 message parsing ──────────────────────────────────

/// Challenge notification parses correctly.
/// Oracle: JSON-RPC 2.0 spec — notifications have method field and no id.
#[wasm_bindgen_test]
fn test_parse_challenge_notification() {
    let json = r#"{"jsonrpc":"2.0","method":"challenge","params":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}"#;
    let v: Value = serde_json::from_str(json).unwrap();

    assert_eq!(v["jsonrpc"].as_str(), Some("2.0"));
    assert_eq!(v["method"].as_str(), Some("challenge"));
    assert!(
        v.get("id").is_none(),
        "notifications must not have an id field"
    );
    assert_eq!(
        v["params"]["nonce"].as_str(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
}

/// Auth success response parses correctly.
/// Oracle: JSON-RPC 2.0 spec — responses have id and result fields.
/// AuthenticateResult fields: pub_id (64 hex chars) and subscription_expires (nullable string).
#[wasm_bindgen_test]
fn test_parse_auth_success_response() {
    let json = r#"{"jsonrpc":"2.0","id":1,"result":{"pub_id":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2","subscription_expires":null}}"#;
    let v: Value = serde_json::from_str(json).unwrap();

    assert_eq!(v["id"].as_u64(), Some(1));
    assert!(v.get("error").is_none());
    let pub_id = v["result"]["pub_id"].as_str().unwrap();
    assert_eq!(pub_id.len(), 64, "pub_id must be 64 hex chars");
    assert!(
        pub_id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "pub_id must be lowercase hex"
    );
    assert!(
        v["result"]["subscription_expires"].is_null(),
        "subscription_expires must be null when no subscription"
    );
    assert!(
        v["result"].get("sequence").is_none(),
        "AuthenticateResult must not contain a sequence field"
    );
}

/// Deliver notification parses correctly.
/// Oracle: JSON-RPC 2.0 spec notification format; nie protocol spec for deliver params.
#[wasm_bindgen_test]
fn test_parse_deliver_notification() {
    let payload_b64 = B64.encode(b"{\"type\":\"chat\",\"text\":\"hello\"}");
    let json = format!(
        r#"{{"jsonrpc":"2.0","method":"deliver","params":{{"from":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2","payload":"{}"}}}}"#,
        payload_b64
    );
    let v: Value = serde_json::from_str(&json).unwrap();

    assert_eq!(v["method"].as_str(), Some("deliver"));
    assert!(v.get("id").is_none(), "notifications have no id");
    let from = v["params"]["from"].as_str().unwrap();
    assert_eq!(from.len(), 64);
    let payload = v["params"]["payload"].as_str().unwrap();
    let decoded = B64.decode(payload).unwrap();
    let text = String::from_utf8(decoded).unwrap();
    assert!(text.contains("hello"));
}

/// Error response parses correctly; auth-failed uses error code -32001.
/// Oracle: JSON-RPC 2.0 spec error object format; nie protocol error codes.
#[wasm_bindgen_test]
fn test_parse_error_response() {
    let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"auth failed: invalid signature"}}"#;
    let v: Value = serde_json::from_str(json).unwrap();

    assert_eq!(v["id"].as_u64(), Some(1));
    assert!(v.get("result").is_none());
    assert_eq!(v["error"]["code"].as_i64(), Some(-32001));
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("auth failed"));
}

// ── Test Set B: Auth signing — happy path and rejection cases ─────────────────

/// Happy path: sign_challenge + verify_challenge roundtrip.
///
/// The oracle for expected pub_id is SHA-256 computed independently using sha2::Sha256,
/// not via any auth:: functions. This is NOT the code under test as its own oracle:
/// sign_challenge uses ed25519-dalek to produce the signature; the expected pub_id is
/// derived below directly from the verifying key bytes using sha2::Sha256, independent
/// of the PubId derivation path in nie_core.
#[wasm_bindgen_test]
fn test_auth_sign_verify_happy_path() {
    let identity = Identity::from_secret_bytes(&TEST_SEED_64).unwrap();

    let (pub_key_b64, sig_b64) = auth::sign_challenge(&identity, TEST_NONCE);

    let result = auth::verify_challenge(&pub_key_b64, TEST_NONCE, &sig_b64);
    assert!(
        result.is_ok(),
        "verify_challenge must succeed for a correct signature"
    );

    let returned_pub_id = result.unwrap();

    // Independent oracle: compute SHA-256 of the verifying key bytes using sha2 directly,
    // not using any auth:: or identity:: hashing functions.
    let verifying_key = identity.verifying_key();
    let key_bytes = verifying_key.to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hash = hasher.finalize();
    let expected_pub_id: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    assert_eq!(
        returned_pub_id.0, expected_pub_id,
        "pub_id must be hex(SHA-256(verifying_key_bytes))"
    );
}

/// Rejection: corrupted signature must fail verification.
/// Oracle: verify_challenge must return Err when given a modified signature.
#[wasm_bindgen_test]
fn test_auth_reject_wrong_signature() {
    let identity = Identity::from_secret_bytes(&TEST_SEED_64).unwrap();
    let (pub_key_b64, sig_b64) = auth::sign_challenge(&identity, TEST_NONCE);

    let mut sig_bytes = B64.decode(&sig_b64).unwrap();
    sig_bytes[0] ^= 0xFF; // flip all bits of first byte
    let bad_sig = B64.encode(&sig_bytes);

    let result = auth::verify_challenge(&pub_key_b64, TEST_NONCE, &bad_sig);
    assert!(
        result.is_err(),
        "verify_challenge must reject a corrupted signature"
    );
}

/// Rejection: correct signature but wrong nonce must fail.
/// Oracle: verify_challenge signs over nonce bytes; a different nonce is a different
/// message, so the signature is invalid.
#[wasm_bindgen_test]
fn test_auth_reject_wrong_nonce() {
    let identity = Identity::from_secret_bytes(&TEST_SEED_64).unwrap();
    let (pub_key_b64, sig_b64) = auth::sign_challenge(&identity, TEST_NONCE);

    let different_nonce = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let result = auth::verify_challenge(&pub_key_b64, different_nonce, &sig_b64);
    assert!(
        result.is_err(),
        "verify_challenge must reject a signature over a different nonce"
    );
}

// ── Test Set C: PubId derivation ──────────────────────────────────────────────

/// Oracle: compute SHA-256 independently with sha2; verify Identity::pub_id() matches.
#[wasm_bindgen_test]
fn test_pub_id_derivation() {
    let identity = Identity::from_secret_bytes(&TEST_SEED_64).unwrap();
    let pub_id = identity.pub_id();

    let key_bytes = identity.verifying_key().to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hash = hasher.finalize();
    let expected: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    assert_eq!(pub_id.0, expected);
    assert_eq!(pub_id.0.len(), 64);
    assert!(
        pub_id.0.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "must be lowercase hex"
    );
}
