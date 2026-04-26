use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use subtle::ConstantTimeEq;
use tokio::sync::broadcast::error::RecvError;

use crate::state::DaemonState;
use crate::token::validate_token_header;
use crate::token::QueryToken;

/// WebSocket handler for /ws/events
/// Streams DaemonEvents as JSON text frames to connected browser clients.
///
/// Accepts auth via:
///   - `Authorization: Bearer <token>` header (programmatic clients)
///   - `?token=<token>` query param (browser WebSocket API, which cannot set headers)
///     The token value is extracted and stored as an extension by the
///     `redact_token_query_param` middleware before the URI is redacted.
pub async fn handle_ws_events(
    ws: WebSocketUpgrade,
    State(state): State<DaemonState>,
    headers: axum::http::HeaderMap,
    query_token: Option<Extension<QueryToken>>,
) -> impl IntoResponse {
    // Token check BEFORE upgrade — reject unauthenticated connections.
    // Check Authorization header first, then the QueryToken extension set by
    // the redact_token_query_param middleware (which has already redacted the URI).
    let auth_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| validate_token_header(h, state.token()))
        .unwrap_or(false)
        || query_token
            .as_ref()
            .map(|Extension(qt)| bool::from(qt.0.as_bytes().ct_eq(state.token().as_bytes())))
            .unwrap_or(false);

    if !auth_ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    ws.on_upgrade(move |socket| ws_client_loop(socket, state))
}

/// Handle a single WebSocket client connection.
async fn ws_client_loop(socket: WebSocket, state: DaemonState) {
    let mut events_rx = state.subscribe_events();
    let (mut sink, mut stream) = socket.split();

    loop {
        tokio::select! {
            // Relay daemon events to browser
            event_result = events_rx.recv() => {
                match event_result {
                    Ok(event) => {
                        // serde_json::to_string on a derived Serialize cannot fail
                        let json = serde_json::to_string(&event).unwrap();
                        if sink.send(Message::Text(json.into())).await.is_err() {
                            // Client disconnected
                            break;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!("WS event stream lagged, dropped {} events", n);
                        // Notify client that events were dropped so it can refetch state.
                        let notice = serde_json::to_string(
                            &crate::types::DaemonEvent::EventsDropped { count: n },
                        )
                        .unwrap();
                        if sink
                            .send(Message::Text(notice.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => {
                        // Broadcast channel shut down (daemon exiting)
                        break;
                    }
                }
            }
            // Handle incoming messages from browser (ping/pong/close)
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::warn!("ws client error: {}", e);
                        break;
                    }
                    Some(Ok(_)) => {
                        // Ping, pong, text, binary — we don't process browser-to-daemon WS messages
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DaemonEvent;

    fn make_state() -> DaemonState {
        DaemonState::new(
            "a".repeat(64),
            "test-token-ws".to_string(),
            None,
            "mainnet".to_string(),
            None,
            None,
        )
    }

    #[test]
    fn test_validate_token_rejects_missing() {
        // No Authorization header → auth_ok = false
        let headers = axum::http::HeaderMap::new();
        let state = make_state();
        let auth_ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|h| validate_token_header(h, state.token()))
            .unwrap_or(false);
        assert!(!auth_ok);
    }

    #[test]
    fn test_validate_token_rejects_wrong() {
        use axum::http::HeaderValue;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong-token"),
        );
        let state = make_state();
        let auth_ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|h| validate_token_header(h, state.token()))
            .unwrap_or(false);
        assert!(!auth_ok);
    }

    #[test]
    fn test_validate_token_accepts_correct() {
        use axum::http::HeaderValue;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token-ws"),
        );
        let state = make_state();
        let auth_ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|h| validate_token_header(h, state.token()))
            .unwrap_or(false);
        assert!(auth_ok);
    }

    #[test]
    fn test_query_param_token_accepts_correct() {
        let state = make_state();
        let query_token: Option<Extension<QueryToken>> =
            Some(Extension(QueryToken("test-token-ws".to_string())));
        let auth_ok = query_token
            .as_ref()
            .map(|Extension(qt)| bool::from(qt.0.as_bytes().ct_eq(state.token().as_bytes())))
            .unwrap_or(false);
        assert!(auth_ok);
    }

    #[test]
    fn test_query_param_token_rejects_wrong() {
        let state = make_state();
        let query_token: Option<Extension<QueryToken>> =
            Some(Extension(QueryToken("wrong-token".to_string())));
        let auth_ok = query_token
            .as_ref()
            .map(|Extension(qt)| bool::from(qt.0.as_bytes().ct_eq(state.token().as_bytes())))
            .unwrap_or(false);
        assert!(!auth_ok);
    }

    #[test]
    fn test_event_serializes_to_json_with_type() {
        let event = DaemonEvent::MessageReceived {
            from: "a".repeat(64),
            from_display_name: "Alice".to_string(),
            text: "hello".to_string(),
            timestamp: "2026-04-19T00:00:00Z".to_string(),
            message_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"message_received\""));
        assert!(json.contains("\"text\":\"hello\""));
    }
}
