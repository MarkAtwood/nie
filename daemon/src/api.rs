use axum::{extract::State, http::StatusCode, Json};
use nie_core::{
    messages::{Chain, ClearMessage, PaymentAction, PaymentRole, PaymentSession, PaymentState},
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

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    zatoshi: u64,
    zec: String,
    network: String,
}

#[derive(Deserialize)]
pub struct PayRequest {
    to_pub_id: String,
    amount_zatoshi: u64,
}

#[derive(Debug, Serialize)]
pub struct PayResponse {
    session_id: String,
    state: String,
}

pub async fn handle_wallet_balance(
    State(state): State<DaemonState>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<ApiError>)> {
    let Some(wallet) = state.wallet_store() else {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            Json(ApiError {
                code: "wallet_not_initialized".to_string(),
                message: "wallet not configured; run 'nie wallet init' first".to_string(),
            }),
        ));
    };
    let balance = wallet.balance_with_confirmations(1).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                code: "wallet_error".to_string(),
                message: format!("balance query failed: {e}"),
            }),
        )
    })?;
    let zatoshi = balance.confirmed_zatoshi;
    // Format: integer ZEC . 8 decimal places
    let zec = format!("{}.{:08}", zatoshi / 100_000_000, zatoshi % 100_000_000);
    Ok(Json(BalanceResponse {
        zatoshi,
        zec,
        network: state.network().to_string(),
    }))
}

pub async fn handle_wallet_pay(
    State(state): State<DaemonState>,
    Json(req): Json<PayRequest>,
) -> Result<Json<PayResponse>, (StatusCode, Json<ApiError>)> {
    // Validate to_pub_id: must be exactly 64 lowercase hex chars (SHA-256 of verifying key).
    if req.to_pub_id.len() != 64
        || !req
            .to_pub_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "invalid_pub_id".to_string(),
                message: "to_pub_id must be 64 lowercase hex characters".to_string(),
            }),
        ));
    }

    // Validate amount.
    let amount = i64::try_from(req.amount_zatoshi).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "invalid_amount".to_string(),
                message: "amount_zatoshi out of range".to_string(),
            }),
        )
    })?;
    if amount == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "invalid_amount".to_string(),
                message: "amount_zatoshi must be greater than zero".to_string(),
            }),
        ));
    }

    let Some(wallet) = state.wallet_store() else {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            Json(ApiError {
                code: "wallet_not_initialized".to_string(),
                message: "wallet not configured; run 'nie wallet init' first".to_string(),
            }),
        ));
    };

    // Check available balance.
    let balance = wallet.balance_with_confirmations(1).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                code: "wallet_error".to_string(),
                message: format!("balance query failed: {e}"),
            }),
        )
    })?;
    if req.amount_zatoshi > balance.confirmed_zatoshi {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "insufficient_balance".to_string(),
                message: format!(
                    "insufficient balance: have {} zatoshi, need {}",
                    balance.confirmed_zatoshi, req.amount_zatoshi
                ),
            }),
        ));
    }

    let session_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    let session = PaymentSession {
        id: session_id,
        chain: Chain::Zcash,
        amount_zatoshi: req.amount_zatoshi,
        peer_pub_id: req.to_pub_id,
        role: PaymentRole::Payer,
        state: PaymentState::Requested,
        created_at: now,
        updated_at: now,
        tx_hash: None,
        address: None,
    };
    wallet.upsert_session(&session).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                code: "wallet_error".to_string(),
                message: format!("session persist failed: {e}"),
            }),
        )
    })?;

    // Broadcast PaymentAction::Request to the relay.
    let payload = serde_json::to_vec(&ClearMessage::Payment {
        session_id,
        action: PaymentAction::Request {
            chain: Chain::Zcash,
            amount_zatoshi: req.amount_zatoshi,
        },
    })
    .unwrap();

    let Some(tx) = state.relay_tx().await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                code: "relay_unavailable".to_string(),
                message: "relay connection not established".to_string(),
            }),
        ));
    };
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

    Ok(Json(PayResponse {
        session_id: session_id.to_string(),
        state: "requested".to_string(),
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
            "mainnet".to_string(),
            None,
            None,
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

    /// Oracle: wallet not initialized → 501 NOT_IMPLEMENTED.
    #[tokio::test]
    async fn test_balance_wallet_not_initialized() {
        let state = make_state(&"a".repeat(64), None);
        let result = handle_wallet_balance(State(state)).await;
        assert!(result.is_err());
        let (status, Json(err)) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(err.code, "wallet_not_initialized");
    }

    /// Oracle: wallet not initialized → pay returns 501 NOT_IMPLEMENTED.
    #[tokio::test]
    async fn test_pay_wallet_not_initialized() {
        let state = make_state(&"a".repeat(64), None);
        let result = handle_wallet_pay(
            State(state),
            Json(PayRequest {
                to_pub_id: "b".repeat(64),
                amount_zatoshi: 10_000,
            }),
        )
        .await;
        assert!(result.is_err());
        let (status, Json(err)) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(err.code, "wallet_not_initialized");
    }

    /// Oracle: amount_zatoshi = 0 → 400 BAD_REQUEST.
    #[tokio::test]
    async fn test_pay_zero_amount_rejected() {
        let state = make_state(&"a".repeat(64), None);
        let result = handle_wallet_pay(
            State(state),
            Json(PayRequest {
                to_pub_id: "b".repeat(64),
                amount_zatoshi: 0,
            }),
        )
        .await;
        assert!(result.is_err());
        let (status, Json(err)) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "invalid_amount");
    }

    /// Oracle: balance endpoint returns zatoshi and formatted zec string.
    /// Uses a real WalletStore with an empty DB (balance = 0).
    #[tokio::test]
    async fn test_balance_empty_wallet_returns_zero() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let ws = nie_wallet::db::WalletStore::new(tmp.path()).await.unwrap();
        let state = DaemonState::new(
            "a".repeat(64),
            "test-token".to_string(),
            None,
            "testnet".to_string(),
            Some(ws),
            None,
        );
        let result = handle_wallet_balance(State(state)).await;
        assert!(result.is_ok(), "empty wallet balance must succeed");
        let Json(resp) = result.unwrap();
        assert_eq!(resp.zatoshi, 0);
        assert_eq!(resp.zec, "0.00000000");
        assert_eq!(resp.network, "testnet");
    }

    /// Oracle: pay with amount > balance → 400 insufficient_balance.
    #[tokio::test]
    async fn test_pay_insufficient_balance_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let ws = nie_wallet::db::WalletStore::new(tmp.path()).await.unwrap();
        let state = DaemonState::new(
            "a".repeat(64),
            "test-token".to_string(),
            None,
            "mainnet".to_string(),
            Some(ws),
            None,
        );
        let result = handle_wallet_pay(
            State(state),
            Json(PayRequest {
                to_pub_id: "b".repeat(64),
                amount_zatoshi: 1_000_000, // more than empty wallet
            }),
        )
        .await;
        assert!(result.is_err());
        let (status, Json(err)) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "insufficient_balance");
    }
}
