//! Slack API types and client.
//!
//! Covers the Events API webhook (incoming from Slack) and the Web API
//! `chat.postMessage` call (outgoing to Slack).

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---- Incoming Slack Events API ----

/// Top-level envelope for a Slack Events API callback.
#[derive(Debug, Deserialize)]
pub struct SlackEvent {
    /// Event type: "url_verification" or "event_callback".
    #[serde(rename = "type")]
    pub event_type: String,
    /// Present only for "url_verification" — Slack URL verification challenge.
    pub challenge: Option<String>,
    /// Present for "event_callback" — the inner event object.
    pub event: Option<SlackInnerEvent>,
}

/// Inner event object inside an "event_callback" envelope.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SlackInnerEvent {
    /// Event type, e.g. "message".
    #[serde(rename = "type")]
    pub event_type: String,
    /// Channel ID where the message was posted.
    pub channel: Option<String>,
    /// User ID of the sender (absent for bot messages).
    pub user: Option<String>,
    /// Message text.
    pub text: Option<String>,
    /// Subtype (e.g. "bot_message") — absent for regular user messages.
    pub subtype: Option<String>,
    /// Bot ID — set for messages posted by bots (including our own bot).
    pub bot_id: Option<String>,
    /// Unique message timestamp (also serves as message ID within a channel).
    pub ts: Option<String>,
}

impl SlackInnerEvent {
    /// Return `true` if this event was posted by a bot (any bot, including ours).
    ///
    /// Skipping bot messages prevents echo loops when the bridge posts to Slack
    /// and then receives the same message back via the Events API.
    pub fn is_bot_message(&self) -> bool {
        self.subtype.as_deref() == Some("bot_message") || self.bot_id.is_some()
    }

    /// Return the plain text body of a regular text message, or `None`.
    pub fn text_body(&self) -> Option<&str> {
        if self.event_type != "message" {
            return None;
        }
        if self.is_bot_message() {
            return None;
        }
        self.text.as_deref()
    }
}

// ---- Signature verification ----

/// Compute the raw HMAC-SHA256 bytes for a Slack signature base string.
///
/// Extracted as a standalone function so the cryptographic computation can be
/// tested against an independently-computed oracle (Python `hmac.new`) without
/// needing a valid (non-stale) timestamp.
fn compute_slack_hmac(signing_secret: &str, timestamp_str: &str, body: &[u8]) -> Result<Vec<u8>> {
    let body_str =
        std::str::from_utf8(body).map_err(|_| anyhow!("Slack request body is not valid UTF-8"))?;
    let base = format!("v0:{timestamp_str}:{body_str}");
    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .map_err(|e| anyhow!("HMAC key error: {e}"))?;
    mac.update(base.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify a Slack request signature.
///
/// Slack signs every incoming webhook request with HMAC-SHA256:
///   key   = signing_secret
///   input = "v0:<timestamp>:<raw_body>"
///   header = "v0=<hex(HMAC)>"
///
/// We also check that the request timestamp is within 5 minutes of now to
/// prevent replay attacks.
///
/// Returns `Ok(())` on success, `Err` if invalid.
pub fn verify_slack_signature(
    signing_secret: &str,
    timestamp_str: &str,
    body: &[u8],
    signature_header: &str,
) -> Result<()> {
    // Replay-attack guard: reject requests older than 5 minutes.
    let ts: i64 = timestamp_str
        .parse()
        .map_err(|_| anyhow!("invalid Slack timestamp: {timestamp_str}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Reject future timestamps beyond clock-skew tolerance (prevents replay with
    // a captured request re-stamped far in the future), and timestamps more than
    // 5 minutes old (prevents replay of old requests).
    if ts > now + 60 || now - ts > 300 {
        return Err(anyhow!("Slack request timestamp too old"));
    }

    let mac_bytes = compute_slack_hmac(signing_secret, timestamp_str, body)?;

    // Strip "v0=" prefix from the provided signature header before comparing raw bytes.
    let provided_hex = signature_header
        .strip_prefix("v0=")
        .ok_or_else(|| anyhow!("Slack signature missing v0= prefix"))?;
    let provided_bytes =
        hex::decode(provided_hex).map_err(|_| anyhow!("Slack signature not valid hex"))?;

    // Constant-time comparison: fold XOR of all byte pairs; any mismatch sets a bit.
    // Length mismatch also fails because HMAC output is always 32 bytes.
    if mac_bytes.len() != provided_bytes.len()
        || mac_bytes
            .iter()
            .zip(provided_bytes.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err(anyhow!("Slack signature mismatch"));
    }
    Ok(())
}

// ---- Slack Web API client ----

#[derive(Serialize)]
struct PostMessageBody<'a> {
    channel: &'a str,
    text: &'a str,
}

/// Thin HTTP client for the Slack Web API.
///
/// Does not implement Debug to prevent accidental logging of the bot token.
pub struct SlackClient {
    bot_token: String,
    http: reqwest::Client,
}

impl SlackClient {
    pub fn new(bot_token: &str) -> Self {
        Self {
            bot_token: bot_token.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Post a plain text message to a Slack channel.
    pub async fn post_message(&self, channel: &str, text: &str) -> Result<()> {
        let body = PostMessageBody { channel, text };
        let resp = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Slack HTTP error: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Slack API error {status}: {err_text}"));
        }
        // Slack returns 200 even for logical errors; check ok field.
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow!("Slack response parse error: {e}"))?;
        if json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let error = json
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(anyhow!("Slack API rejected message: {error}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_bot_message_detects_subtype() {
        let event = SlackInnerEvent {
            event_type: "message".to_string(),
            channel: None,
            user: None,
            text: Some("hello".to_string()),
            subtype: Some("bot_message".to_string()),
            bot_id: None,
            ts: None,
        };
        assert!(event.is_bot_message());
    }

    #[test]
    fn is_bot_message_detects_bot_id() {
        let event = SlackInnerEvent {
            event_type: "message".to_string(),
            channel: None,
            user: Some("U123".to_string()),
            text: Some("hello".to_string()),
            subtype: None,
            bot_id: Some("B456".to_string()),
            ts: None,
        };
        assert!(event.is_bot_message());
    }

    #[test]
    fn is_bot_message_false_for_user_message() {
        let event = SlackInnerEvent {
            event_type: "message".to_string(),
            channel: None,
            user: Some("U123".to_string()),
            text: Some("hello".to_string()),
            subtype: None,
            bot_id: None,
            ts: None,
        };
        assert!(!event.is_bot_message());
    }

    #[test]
    fn text_body_returns_text_for_user_message() {
        let event = SlackInnerEvent {
            event_type: "message".to_string(),
            channel: None,
            user: Some("U123".to_string()),
            text: Some("hello world".to_string()),
            subtype: None,
            bot_id: None,
            ts: None,
        };
        assert_eq!(event.text_body(), Some("hello world"));
    }

    #[test]
    fn text_body_returns_none_for_bot_message() {
        let event = SlackInnerEvent {
            event_type: "message".to_string(),
            channel: None,
            user: None,
            text: Some("from bot".to_string()),
            subtype: Some("bot_message".to_string()),
            bot_id: Some("B123".to_string()),
            ts: None,
        };
        assert_eq!(event.text_body(), None);
    }

    #[test]
    fn text_body_returns_none_for_non_message_event() {
        let event = SlackInnerEvent {
            event_type: "reaction_added".to_string(),
            channel: None,
            user: Some("U123".to_string()),
            text: None,
            subtype: None,
            bot_id: None,
            ts: None,
        };
        assert_eq!(event.text_body(), None);
    }

    #[test]
    fn verify_signature_rejects_mismatch() {
        // Timestamp is far in the future to pass the time check.
        let future_ts = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()) as i64;
        let ts = future_ts.to_string();
        let body = b"test body";
        // Use an incorrect signature.
        let result = verify_slack_signature("correct_secret", &ts, body, "v0=incorrect_signature");
        assert!(result.is_err());
    }

    #[test]
    fn verify_signature_rejects_old_timestamp() {
        // Timestamp 10 minutes in the past.
        let old_ts = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600) as i64;
        let ts = old_ts.to_string();
        let result = verify_slack_signature("secret", &ts, b"body", "v0=anything");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("timestamp too old"));
    }

    /// Oracle: HMAC-SHA256 computed with Python's independent implementation:
    ///   import hmac, hashlib
    ///   secret = b"test_signing_secret"
    ///   ts = "1609459200"
    ///   body = b"test=body"
    ///   base = f"v0:{ts}:{body.decode()}".encode()
    ///   hex_sig = hmac.new(secret, base, hashlib.sha256).hexdigest()
    ///   # result: f8df6d84b5326caa77e72d49b8c10603dd30bc2deb26fe8c9051276bacbe0fd0
    #[test]
    fn verify_signature_hmac_oracle() {
        // This test proves compute_slack_hmac is correct per the Slack signing spec,
        // using a value computed by Python's hmac module as the independent oracle.
        let sig_bytes =
            compute_slack_hmac("test_signing_secret", "1609459200", b"test=body").unwrap();
        assert_eq!(
            hex::encode(sig_bytes),
            "f8df6d84b5326caa77e72d49b8c10603dd30bc2deb26fe8c9051276bacbe0fd0"
        );
    }

    #[test]
    fn verify_signature_accepts_correct_signature() {
        // Integration test: verify_slack_signature accepts a correctly-computed sig.
        // The oracle test above guarantees compute_slack_hmac is correct;
        // this test guarantees verify_slack_signature uses it correctly.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = (now + 1).to_string();
        let body = b"test=body";
        let secret = "test_signing_secret";

        let mac_bytes = compute_slack_hmac(secret, &ts, body).unwrap();
        let expected_sig = format!("v0={}", hex::encode(mac_bytes));

        let result = verify_slack_signature(secret, &ts, body, &expected_sig);
        assert!(
            result.is_ok(),
            "correct signature must verify: {:?}",
            result
        );
    }
}
