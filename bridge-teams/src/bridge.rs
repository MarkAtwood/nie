//! Teams ↔ nie bridge: bidirectional message forwarding.
//!
//! # Architecture
//!
//! ```text
//! Teams outgoing webhook ──► axum handler ──► mpsc channel ──► nie broadcast
//!        ▲                                                           │
//!        │                                                           ▼
//! Teams incoming webhook ◄───────────────────────────────────── nie deliver
//! ```
//!
//! Teams sends incoming messages to our HTTP server via an outgoing webhook
//! (triggered when a user posts in the configured Teams channel).
//! We verify the HMAC signature and forward user messages to the nie relay.
//! When the nie relay delivers messages, we post them to Teams via the
//! incoming webhook connector URL.

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
use crate::teams::{verify_teams_signature, TeamsActivity, TeamsClient};

/// Format a nie message for display in Teams.
///
/// Uses `**bold**` Markdown so the nie sender stands out from the message text.
pub fn format_for_teams(sender_pub_id: &str, text: &str, prefix: Option<&str>) -> String {
    let short_id = &sender_pub_id[..sender_pub_id.len().min(8)];
    match prefix {
        Some(p) => format!("{p} **{short_id}**: {text}"),
        None => format!("**{short_id}**: {text}"),
    }
}

/// Format a Teams message for forwarding to nie.
pub fn format_for_nie(sender_name: &str, text: &str) -> String {
    format!("[Teams/{sender_name}] {text}")
}

// ---- axum state for the Teams webhook endpoint ----

#[derive(Clone)]
struct TeamsState {
    security_token: String,
    tx: tokio::sync::mpsc::Sender<String>,
}

/// Axum handler for `POST /teams/webhook`.
///
/// Verifies the Teams HMAC signature and forwards user messages to the
/// bridge's internal mpsc channel.  Responds with an empty JSON object
/// (Teams ignores the response body for bridged messages).
async fn teams_webhook(
    State(state): State<TeamsState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, StatusCode> {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if verify_teams_signature(&state.security_token, &body, auth).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let activity: TeamsActivity =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(text) = activity.text_body() {
        let sender = activity
            .from
            .as_ref()
            .and_then(|f| f.name.as_deref())
            .unwrap_or("unknown");
        let nie_text = format_for_nie(sender, text);
        // Back-pressure: drop the message rather than block the HTTP handler.
        if state.tx.try_send(nie_text).is_err() {
            tracing::warn!("Teams→nie channel full; message dropped");
        }
    }

    Ok(Json(serde_json::json!({})))
}

// ---- Handle an incoming nie deliver event ----

async fn handle_nie_deliver(
    params: Option<Value>,
    own_pub_id: &str,
    teams: &TeamsClient,
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
    let formatted = format_for_teams(&deliver.from, &text, bridge_prefix);
    if let Err(e) = teams.post_message(&formatted).await {
        tracing::warn!("Teams post_message failed: {e}");
    }
}

// ---- Main bridge loop ----

pub async fn run(config: &BridgeConfig) -> Result<()> {
    let identity = nie_core::keyfile::load_identity(&config.keyfile, false)?;
    let own_pub_id = identity.pub_id().0.clone();

    // Connect to the nie relay with transparent reconnection.
    let mut conn =
        nie_core::transport::connect_with_retry(config.relay_url.clone(), identity, false, None);

    // Teams client for outbound sends.
    let teams = Arc::new(TeamsClient::new(&config.teams_incoming_webhook_url));
    let bridge_prefix = config.bridge_prefix.clone();
    let listen_port = config.listen_port;

    // Channel: Teams events → nie broadcast.
    let (teams_tx, mut teams_rx) = tokio::sync::mpsc::channel::<String>(64);

    // Start the Teams outgoing webhook HTTP server.
    {
        let state = TeamsState {
            security_token: config.teams_security_token.clone(),
            tx: teams_tx,
        };
        let app = axum::Router::new()
            .route("/teams/webhook", axum::routing::post(teams_webhook))
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{listen_port}")).await?;
        tracing::info!("Teams webhook server listening on port {listen_port}");
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
    }

    tracing::info!("bridge-teams connected to relay as {}", &own_pub_id[..8]);

    // Main event loop.
    loop {
        tokio::select! {
            // Teams message → nie broadcast.
            maybe_text = teams_rx.recv() => {
                let Some(text) = maybe_text else { break };
                let payload = serde_json::to_vec(&ClearMessage::Chat { text }).unwrap();
                let Ok(padded) = pad(&payload) else {
                    tracing::warn!("Teams message too large to pad; dropped");
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
            // nie relay event → Teams post.
            maybe_event = conn.rx.recv() => {
                let Some(event) = maybe_event else { break };
                match event {
                    ClientEvent::Message(notif) => {
                        if notif.method == rpc_methods::DELIVER {
                            handle_nie_deliver(
                                notif.params,
                                &own_pub_id,
                                &teams,
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
    fn format_for_teams_with_prefix() {
        let result = format_for_teams("abcdef1234567890", "hello", Some("[nie]"));
        assert_eq!(result, "[nie] **abcdef12**: hello");
    }

    #[test]
    fn format_for_teams_without_prefix() {
        let result = format_for_teams("abcdef1234567890", "hello", None);
        assert_eq!(result, "**abcdef12**: hello");
    }

    #[test]
    fn format_for_teams_short_id() {
        let result = format_for_teams("abc", "hi", None);
        assert_eq!(result, "**abc**: hi");
    }

    #[test]
    fn format_for_nie_includes_sender_and_text() {
        let result = format_for_nie("Alice", "hello world");
        assert_eq!(result, "[Teams/Alice] hello world");
    }
}
