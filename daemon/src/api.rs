use axum::{extract::State, http::StatusCode, Json};
use nie_core::{
    messages::ClearMessage,
    protocol::{rpc_methods, BroadcastParams, JsonRpcRequest},
    transport::next_request_id,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::DaemonState;
use crate::types::UserInfo;

#[derive(Serialize)]
pub struct WhoamiResponse {
    pub_id: String,
    display_name: String,
}

#[derive(Serialize)]
pub struct UsersResponse {
    online: Vec<UserInfo>,
    offline: Vec<UserInfo>,
}

#[derive(Deserialize)]
pub struct SendRequest {
    text: String,
}

#[derive(Debug, Serialize)]
pub struct SendResponse {
    message_id: String,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    code: String,
    message: String,
}

const MAX_TEXT_BYTES: usize = 65536;

pub async fn handle_whoami(State(state): State<DaemonState>) -> Json<WhoamiResponse> {
    let pub_id = state.my_pub_id().to_string();
    let display_name = state
        .display_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Fallback: first 8 chars of pub_id + ellipsis
            if pub_id.len() >= 8 {
                format!("{}…", &pub_id[..8])
            } else {
                pub_id.clone()
            }
        });
    Json(WhoamiResponse {
        pub_id,
        display_name,
    })
}

pub async fn handle_users(State(state): State<DaemonState>) -> Json<UsersResponse> {
    let dir = state.directory_snapshot().await;
    Json(UsersResponse {
        online: dir.online,
        offline: dir.offline,
    })
}

pub async fn handle_send(
    State(state): State<DaemonState>,
    Json(req): Json<SendRequest>,
) -> Result<Json<SendResponse>, (StatusCode, Json<ApiError>)> {
    if req.text.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "invalid_request".to_string(),
                message: "text must not be empty".to_string(),
            }),
        ));
    }
    if req.text.len() > MAX_TEXT_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ApiError {
                code: "payload_too_large".to_string(),
                message: format!("text exceeds {} bytes", MAX_TEXT_BYTES),
            }),
        ));
    }

    // serde_json::to_vec on a derived Serialize cannot fail
    let payload: Vec<u8> = serde_json::to_vec(&ClearMessage::Chat { text: req.text }).unwrap();

    let Some(tx) = state.relay_tx().await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                code: "relay_unavailable".to_string(),
                message: "relay connection not established".to_string(),
            }),
        ));
    };

    // JsonRpcRequest::new on derived Serialize params cannot fail
    let rpc_req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload },
    )
    .unwrap();

    tx.send(rpc_req).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                code: "relay_unavailable".to_string(),
                message: "relay send failed".to_string(),
            }),
        )
    })?;

    Ok(Json(SendResponse {
        message_id: Uuid::new_v4().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DaemonState;

    fn make_state(pub_id: &str, display_name: Option<&str>) -> DaemonState {
        DaemonState::new(
            pub_id.to_string(),
            "test-token".to_string(),
            display_name.map(|s| s.to_string()),
        )
    }

    #[tokio::test]
    async fn test_whoami_returns_valid_pubid() {
        let pub_id = "a".repeat(64); // 64 hex chars (all 'a')
        let state = make_state(&pub_id, None);
        let Json(resp) = handle_whoami(State(state)).await;
        assert_eq!(resp.pub_id.len(), 64, "pub_id must be 64 chars");
        assert!(
            resp.pub_id.chars().all(|c| c.is_ascii_hexdigit()),
            "pub_id must be hex: {}",
            resp.pub_id
        );
    }

    #[tokio::test]
    async fn test_whoami_display_name_fallback() {
        let pub_id = "abcdef1234567890".repeat(4); // 64 chars
        let state = make_state(&pub_id, None);
        let Json(resp) = handle_whoami(State(state)).await;
        // Fallback is first 8 chars + ellipsis
        assert!(
            resp.display_name.starts_with("abcdef12"),
            "display_name={}",
            resp.display_name
        );
        assert!(
            resp.display_name.ends_with('…'),
            "display_name={}",
            resp.display_name
        );
    }

    #[tokio::test]
    async fn test_whoami_explicit_display_name() {
        let state = make_state(&"a".repeat(64), Some("Alice"));
        let Json(resp) = handle_whoami(State(state)).await;
        assert_eq!(resp.display_name, "Alice");
    }

    #[tokio::test]
    async fn test_users_empty_before_directory() {
        let state = make_state(&"a".repeat(64), None);
        let Json(resp) = handle_users(State(state)).await;
        assert!(resp.online.is_empty(), "online should be empty");
        assert!(resp.offline.is_empty(), "offline should be empty");
    }

    #[tokio::test]
    async fn test_users_after_directory_update() {
        let state = make_state(&"a".repeat(64), None);
        let online = vec![UserInfo {
            pub_id: "b".repeat(64),
            display_name: "Bob".to_string(),
            sequence: 1,
        }];
        state.update_directory(online.clone(), vec![]).await;
        let Json(resp) = handle_users(State(state)).await;
        assert_eq!(resp.online.len(), 1);
        assert_eq!(resp.online[0].pub_id, "b".repeat(64));
    }

    #[tokio::test]
    async fn test_send_empty_text_rejected() {
        let state = make_state(&"a".repeat(64), None);
        let result = handle_send(
            State(state),
            Json(SendRequest {
                text: "".to_string(),
            }),
        )
        .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_send_too_long_rejected() {
        let state = make_state(&"a".repeat(64), None);
        let big_text = "x".repeat(65537);
        let result = handle_send(State(state), Json(SendRequest { text: big_text })).await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_send_relay_unavailable() {
        let state = make_state(&"a".repeat(64), None);
        let result = handle_send(
            State(state),
            Json(SendRequest {
                text: "hello".to_string(),
            }),
        )
        .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_send_returns_uuid_format() {
        let state = make_state(&"a".repeat(64), None);
        let (tx, mut _rx) = tokio::sync::mpsc::channel(10);
        state.set_relay_tx(tx).await;

        let result = handle_send(
            State(state),
            Json(SendRequest {
                text: "hello world".to_string(),
            }),
        )
        .await;
        assert!(result.is_ok(), "send should succeed");
        let Json(resp) = result.unwrap();
        // UUID format: 8-4-4-4-12 = 36 chars total with hyphens
        assert_eq!(
            resp.message_id.len(),
            36,
            "UUID must be 36 chars: {}",
            resp.message_id
        );
        let parts: Vec<&str> = resp.message_id.split('-').collect();
        assert_eq!(
            parts.len(),
            5,
            "UUID must have 5 parts: {}",
            resp.message_id
        );
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }
}
