use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Incoming Matrix Application Service transaction.
#[derive(Debug, Deserialize)]
pub struct AsTransaction {
    pub events: Vec<MatrixEvent>,
}

/// One Matrix room event from the homeserver.
///
/// `room_id` is intentionally absent: the bridge always routes to the single
/// configured room and does not need to inspect the event's room.
/// Unknown fields from the homeserver (including room_id) are ignored by serde.
#[derive(Debug, Deserialize)]
pub struct MatrixEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub sender: String,
    pub content: serde_json::Value,
    pub event_id: String,
}

/// If `event` is a plain text message (m.room.message / m.text), return the body.
pub fn text_body(event: &MatrixEvent) -> Option<&str> {
    if event.event_type != "m.room.message" {
        return None;
    }
    if event.content.get("msgtype")?.as_str()? != "m.text" {
        return None;
    }
    event.content.get("body")?.as_str()
}

/// Extract the Matrix localpart from a full MXID (@localpart:server).
pub fn mxid_localpart(mxid: &str) -> &str {
    mxid.trim_start_matches('@')
        .split(':')
        .next()
        .unwrap_or(mxid)
}

#[derive(Serialize)]
struct TextMessageContent<'a> {
    msgtype: &'a str,
    body: &'a str,
}

/// Thin async HTTP client for the Matrix Client-Server API.
pub struct MatrixClient {
    homeserver: String,
    as_token: String,
    http: reqwest::Client,
}

impl MatrixClient {
    pub fn new(homeserver: &str, as_token: &str) -> Self {
        Self {
            homeserver: homeserver.trim_end_matches('/').to_string(),
            as_token: as_token.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Send a plain text message to a Matrix room.
    pub async fn send_text(&self, room_id: &str, text: &str) -> Result<()> {
        let txn_id = Uuid::new_v4();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.homeserver,
            urlencoding::encode(room_id),
            txn_id,
        );
        let body = TextMessageContent { msgtype: "m.text", body: text };
        let resp = self
            .http
            .put(&url)
            .query(&[("access_token", &self.as_token)])
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("Matrix HTTP error: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Matrix send failed {status}: {err_text}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_body_accepts_mtext() {
        let event = MatrixEvent {
            event_type: "m.room.message".to_string(),
            sender: "@alice:example.com".to_string(),
            content: json!({"msgtype": "m.text", "body": "hello"}),
            event_id: "$xyz".to_string(),
        };
        assert_eq!(text_body(&event), Some("hello"));
    }

    #[test]
    fn text_body_rejects_non_message() {
        let event = MatrixEvent {
            event_type: "m.room.member".to_string(),
            sender: "@alice:example.com".to_string(),
            content: json!({"membership": "join"}),
            event_id: "$xyz".to_string(),
        };
        assert_eq!(text_body(&event), None);
    }

    #[test]
    fn text_body_rejects_mimage() {
        let event = MatrixEvent {
            event_type: "m.room.message".to_string(),
            sender: "@alice:example.com".to_string(),
            content: json!({"msgtype": "m.image", "body": "photo.jpg", "url": "mxc://abc"}),
            event_id: "$xyz".to_string(),
        };
        assert_eq!(text_body(&event), None);
    }

    #[test]
    fn as_transaction_deserializes() {
        let json = r#"{"events":[{"type":"m.room.message","room_id":"!abc:example.com","sender":"@alice:example.com","content":{"msgtype":"m.text","body":"hi"},"event_id":"$xyz"}]}"#;
        let txn: AsTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(txn.events.len(), 1);
        assert_eq!(txn.events[0].sender, "@alice:example.com");
        assert_eq!(text_body(&txn.events[0]), Some("hi"));
    }

    #[test]
    fn mxid_localpart_strips_server() {
        assert_eq!(mxid_localpart("@alice:example.com"), "alice");
    }

    #[test]
    fn mxid_localpart_strips_at() {
        assert_eq!(mxid_localpart("@niebridge:matrix.org"), "niebridge");
    }
}
