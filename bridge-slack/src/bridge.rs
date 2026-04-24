//! Slack ↔ nie bridge: bidirectional message forwarding.
//!
//! # Architecture
//!
//! ```text
//! Slack Events API ──► axum handler ──► mpsc channel ──► nie broadcast
//!        ▲                                                      │
//!        │                                                      ▼
//! Slack Web API ◄─────────────────────────────────────── nie deliver
//! ```
//!
//! The Slack Events API pushes incoming messages to our HTTP server.
//! We verify the request signature and forward user messages to the nie relay.
//! When the nie relay delivers messages, we post them to the Slack channel.

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use nie_core::messages::{pad, unpad, ClearMessage};
use nie_core::protocol::{rpc_methods, BroadcastParams, DeliverParams, JsonRpcRequest};
use nie_core::transport::{next_request_id, ClientEvent};
use serde_json::Value;
use std::sync::Arc;

use crate::config::BridgeConfig;
use crate::slack::{verify_slack_signature, SlackClient, SlackEvent};

/// Format a nie message for display in Slack.
///
/// Uses `*bold*` Slack markup so the nie sender stands out from the message text.
pub fn format_for_slack(sender_pub_id: &str, text: &str, prefix: Option<&str>) -> String {
    let short_id = &sender_pub_id[..sender_pub_id.len().min(8)];
    match prefix {
        Some(p) => format!("{p} *{short_id}*: {text}"),
        None => format!("*{short_id}*: {text}"),
    }
}

/// Format a Slack message for forwarding to nie.
pub fn format_for_nie(slack_user: &str, text: &str) -> String {
    format!("[Slack/{slack_user}] {text}")
}

// ---- axum state for the Slack events endpoint ----

#[derive(Clone)]
struct SlackState {
    signing_secret: String,
    tx: tokio::sync::mpsc::Sender<String>,
}

/// Axum handler for `POST /slack/events`.
///
/// Verifies the Slack request signature, handles URL verification, and
/// forwards user messages to the bridge's internal mpsc channel.
async fn slack_events(
    State(state): State<SlackState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, StatusCode> {
    // Extract signature headers.
    let ts = headers
        .get("X-Slack-Request-Timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sig = headers
        .get("X-Slack-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Verify signature — reject unsigned or tampered requests.
    if verify_slack_signature(&state.signing_secret, ts, &body, sig).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let envelope: SlackEvent =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Handle URL verification challenge (Slack sends this when you first configure the endpoint).
    if envelope.event_type == "url_verification" {
        let challenge = envelope.challenge.unwrap_or_default();
        return Ok(Json(serde_json::json!({ "challenge": challenge })));
    }

    // Handle message events.
    if envelope.event_type == "event_callback" {
        if let Some(inner) = envelope.event {
            if let Some(text) = inner.text_body() {
                let user = inner.user.as_deref().unwrap_or("unknown");
                let nie_text = format_for_nie(user, text);
                // Back-pressure: drop the message rather than block the HTTP handler.
                if state.tx.try_send(nie_text).is_err() {
                    tracing::warn!("Slack→nie channel full; message dropped");
                }
            }
        }
    }

    Ok(Json(serde_json::json!({})))
}

// ---- Handle an incoming nie deliver event ----

async fn handle_nie_deliver(
    params: Option<Value>,
    own_pub_id: &str,
    slack: &SlackClient,
    channel_id: &str,
    bridge_prefix: Option<&str>,
) {
    let Some(params) = params else { return };
    let Ok(deliver) = serde_json::from_value::<DeliverParams>(params) else {
        return;
    };
    if deliver.from == own_pub_id {
        return; // skip own echo
    }
    let Ok(msg) = unpad(&deliver.payload) else {
        return;
    };
    let Ok(clear) = serde_json::from_slice::<ClearMessage>(&msg) else {
        return;
    };
    let ClearMessage::Chat { text } = clear else {
        return;
    };
    // Echo suppression: the Slack bot token causes outbound messages to arrive
    // back as bot_message events; `is_bot_message()` in SlackInnerEvent filters
    // those before they reach this handler.
    let formatted = format_for_slack(&deliver.from, &text, bridge_prefix);
    if let Err(e) = slack.post_message(channel_id, &formatted).await {
        tracing::warn!("Slack post_message failed: {e}");
    }
}

// ---- Main bridge loop ----

pub async fn run(config: &BridgeConfig) -> Result<()> {
    let identity = nie_core::keyfile::load_identity(&config.keyfile, false)?;
    let own_pub_id = identity.pub_id().0.clone();

    // Connect to the nie relay with transparent reconnection.
    let mut conn =
        nie_core::transport::connect_with_retry(config.relay_url.clone(), identity, false, None);

    // Slack client for outbound sends.
    let slack = Arc::new(SlackClient::new(&config.slack_bot_token));
    let channel_id = config.slack_channel_id.clone();
    let bridge_prefix = config.bridge_prefix.clone();
    let listen_port = config.listen_port;

    // Channel: Slack events → nie broadcast.
    let (slack_tx, mut slack_rx) = tokio::sync::mpsc::channel::<String>(64);

    // Start the Slack events HTTP server.
    {
        let state = SlackState {
            signing_secret: config.slack_signing_secret.clone(),
            tx: slack_tx,
        };
        let app = axum::Router::new()
            .route("/slack/events", axum::routing::post(slack_events))
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{listen_port}")).await?;
        tracing::info!("Slack events server listening on port {listen_port}");
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
    }

    tracing::info!("bridge-slack connected to relay as {}", &own_pub_id[..8]);

    // Main event loop.
    loop {
        tokio::select! {
            // Slack message → nie broadcast.
            maybe_text = slack_rx.recv() => {
                let Some(text) = maybe_text else { break };
                let payload = serde_json::to_vec(&ClearMessage::Chat { text }).unwrap();
                let Ok(padded) = pad(&payload) else {
                    tracing::warn!("Slack message too large to pad; dropped");
                    continue;
                };
                let Ok(rpc) = JsonRpcRequest::new(
                    next_request_id(),
                    rpc_methods::BROADCAST,
                    BroadcastParams { payload: padded },
                ) else {
                    continue;
                };
                if conn.tx.send(rpc).await.is_err() {
                    tracing::warn!("relay disconnected while sending");
                    break;
                }
            }
            // nie relay event → Slack post.
            maybe_event = conn.rx.recv() => {
                let Some(event) = maybe_event else { break };
                match event {
                    ClientEvent::Message(notif) => {
                        if notif.method == rpc_methods::DELIVER {
                            handle_nie_deliver(
                                notif.params,
                                &own_pub_id,
                                &slack,
                                &channel_id,
                                bridge_prefix.as_deref(),
                            )
                            .await;
                        }
                    }
                    ClientEvent::Reconnecting { delay_secs } => {
                        tracing::info!("relay reconnecting in {delay_secs}s");
                    }
                    ClientEvent::Disconnected => {
                        tracing::error!("relay disconnected");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_for_slack_with_prefix() {
        let result = format_for_slack("abcdef1234567890", "hello", Some("[nie]"));
        assert_eq!(result, "[nie] *abcdef12*: hello");
    }

    #[test]
    fn format_for_slack_without_prefix() {
        let result = format_for_slack("abcdef1234567890", "hello", None);
        assert_eq!(result, "*abcdef12*: hello");
    }

    #[test]
    fn format_for_slack_short_id() {
        let result = format_for_slack("abc", "hi", None);
        assert_eq!(result, "*abc*: hi");
    }

    #[test]
    fn format_for_nie_includes_user_and_text() {
        let result = format_for_nie("U123456", "hello world");
        assert_eq!(result, "[Slack/U123456] hello world");
    }

}
