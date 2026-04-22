//! Microsoft Teams API types and client.
//!
//! Covers the outgoing webhook endpoint (incoming from Teams) and the
//! incoming webhook connector (outgoing to Teams).
//!
//! # Teams outgoing webhook authentication
//!
//! Teams signs every outgoing webhook request with HMAC-SHA256:
//!   key   = base64_decode(security_token)
//!   input = raw request body bytes
//!   header = "HMAC <base64(HMAC-SHA256(key, body))>"
//!
//! # Teams incoming webhook
//!
//! Post a JSON payload with a "text" field to the connector URL.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---- Incoming Teams outgoing webhook payload ----

/// Activity object sent by Teams outgoing webhooks.
#[derive(Debug, Deserialize)]
pub struct TeamsActivity {
    /// Activity type (typically "message").
    #[serde(rename = "type")]
    pub activity_type: String,
    /// Display name of the sender.
    pub from: Option<TeamsFrom>,
    /// Plain text of the message.
    pub text: Option<String>,
}

/// Sender identity within a Teams activity.
#[derive(Debug, Deserialize)]
pub struct TeamsFrom {
    /// Unique user ID.
    #[allow(dead_code)]
    pub id: Option<String>,
    /// Display name.
    pub name: Option<String>,
}

impl TeamsActivity {
    /// Return the plain text body for a user message, or `None`.
    ///
    /// Teams outgoing webhooks may strip @mention markup from the text; we
    /// return the text as-is and let the nie layer decide how to display it.
    pub fn text_body(&self) -> Option<&str> {
        if self.activity_type != "message" {
            return None;
        }
        // Strip leading @mention if present (Teams prepends "<at>BotName</at> " to text).
        let raw = self.text.as_deref()?;
        // Remove any leading XML <at>…</at> mention tag.
        let stripped = if raw.starts_with("<at>") {
            raw.find("</at>")
                .map(|i| raw[i + 5..].trim_start())
                .unwrap_or(raw)
        } else {
            raw.trim_start()
        };
        if stripped.is_empty() {
            None
        } else {
            Some(stripped)
        }
    }
}

// ---- Signature verification ----

/// Verify a Teams outgoing webhook request signature.
///
/// Teams signs requests as:
///   key   = base64_decode(security_token)
///   hmac  = HMAC-SHA256(key, body)
///   header = "HMAC <base64(hmac)>"
///
/// Returns `Ok(())` on success, `Err` if the signature is invalid.
pub fn verify_teams_signature(security_token: &str, body: &[u8], auth_header: &str) -> Result<()> {
    // Decode the security token from base64.
    let key = B64
        .decode(security_token)
        .map_err(|e| anyhow!("invalid security_token base64: {e}"))?;

    // Compute HMAC-SHA256 of the body.
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|e| anyhow!("HMAC key error: {e}"))?;
    mac.update(body);
    let computed = format!("HMAC {}", B64.encode(mac.finalize().into_bytes()));

    // Constant-time comparison.
    if !constant_time_eq(computed.as_bytes(), auth_header.as_bytes()) {
        return Err(anyhow!("Teams signature mismatch"));
    }
    Ok(())
}

/// Constant-time equality check to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---- Teams incoming webhook client ----

#[derive(Serialize)]
struct PostMessageBody<'a> {
    text: &'a str,
}

/// Client for posting messages to a Teams channel via an incoming webhook connector.
///
/// Does not implement Debug to prevent accidental logging of the webhook URL
/// (which contains an embedded credential).
pub struct TeamsClient {
    webhook_url: String,
    http: reqwest::Client,
}

impl TeamsClient {
    pub fn new(webhook_url: &str) -> Self {
        Self {
            webhook_url: webhook_url.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Post a plain text message to the Teams channel.
    pub async fn post_message(&self, text: &str) -> Result<()> {
        let body = PostMessageBody { text };
        let resp = self
            .http
            .post(&self.webhook_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Teams HTTP error: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Teams webhook error {status}: {err_text}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_body_returns_text_for_message() {
        let act = TeamsActivity {
            activity_type: "message".to_string(),
            from: None,
            text: Some("hello world".to_string()),
        };
        assert_eq!(act.text_body(), Some("hello world"));
    }

    #[test]
    fn text_body_strips_at_mention_prefix() {
        let act = TeamsActivity {
            activity_type: "message".to_string(),
            from: None,
            text: Some("<at>BridgeBot</at> hello world".to_string()),
        };
        assert_eq!(act.text_body(), Some("hello world"));
    }

    #[test]
    fn text_body_returns_none_for_non_message() {
        let act = TeamsActivity {
            activity_type: "invoke".to_string(),
            from: None,
            text: Some("ignored".to_string()),
        };
        assert_eq!(act.text_body(), None);
    }

    #[test]
    fn text_body_returns_none_for_empty_text_after_strip() {
        let act = TeamsActivity {
            activity_type: "message".to_string(),
            from: None,
            text: Some("<at>Bot</at>  ".to_string()),
        };
        assert_eq!(act.text_body(), None);
    }

    #[test]
    fn verify_signature_rejects_mismatch() {
        // key = base64("testkey") = "dGVzdGtleQ=="
        let key_bytes = b"testkey";
        let token = B64.encode(key_bytes);
        let body = b"test body";
        let result = verify_teams_signature(&token, body, "HMAC wrongsignature");
        assert!(result.is_err());
    }

    #[test]
    fn verify_signature_rejects_bad_token_base64() {
        let result = verify_teams_signature("!!!not base64!!!", b"body", "HMAC abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }

    #[test]
    fn verify_signature_accepts_correct_signature() {
        // key = raw bytes "testkey"
        let key_bytes = b"testkey";
        let token = B64.encode(key_bytes);
        let body = b"test body";

        // Compute expected signature using the same algorithm.
        let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
        mac.update(body);
        let expected = format!("HMAC {}", B64.encode(mac.finalize().into_bytes()));

        let result = verify_teams_signature(&token, body, &expected);
        assert!(
            result.is_ok(),
            "correct signature must verify: {:?}",
            result
        );
    }
}
