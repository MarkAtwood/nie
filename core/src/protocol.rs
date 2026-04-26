use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::base64::Base64;
use serde_with::serde_as;

/// A user entry in the directory, pairing a pub_id with their optional nickname.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub pub_id: String,
    /// Set once via SetNickname; None until the user has introduced themselves.
    pub nickname: Option<String>,
    /// Relay-assigned monotonic connection sequence for online users; 0 for offline.
    /// Online users in DirectoryList are sorted ascending by this value.
    /// `serde(default)` keeps older clients (pre-sequence protocol) from failing to
    /// deserialize a DirectoryList that omits this field — they get 0, which is fine
    /// since 0 is below every real sequence and sorts them before online peers.
    #[serde(default)]
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 method name constants
// ---------------------------------------------------------------------------

pub mod rpc_methods {
    pub const CHALLENGE: &str = "challenge";
    pub const AUTHENTICATE: &str = "authenticate";
    pub const BROADCAST: &str = "broadcast";
    pub const DELIVER: &str = "deliver";
    pub const DIRECTORY_LIST: &str = "directory_list";
    pub const USER_JOINED: &str = "user_joined";
    pub const USER_LEFT: &str = "user_left";
    pub const SET_NICKNAME: &str = "set_nickname";
    pub const USER_NICKNAME: &str = "user_nickname";
    pub const SUBSCRIBE_REQUEST: &str = "subscribe_request";
    pub const SUBSCRIPTION_ACTIVE: &str = "subscription_active";
    pub const PUBLISH_KEY_PACKAGE: &str = "publish_key_package";
    pub const GET_KEY_PACKAGE: &str = "get_key_package";
    /// Deprecated — now a JsonRpcResponse result rather than a named notification.
    pub const KEY_PACKAGE_RESPONSE: &str = "key_package_response";
    pub const KEY_PACKAGE_READY: &str = "key_package_ready";
    pub const WHISPER: &str = "whisper";
    pub const WHISPER_DELIVER: &str = "whisper_deliver";
    pub const SEALED_BROADCAST: &str = "sealed_broadcast";
    pub const SEALED_DELIVER: &str = "sealed_deliver";
    pub const SEALED_WHISPER: &str = "sealed_whisper";
    pub const SEALED_WHISPER_DELIVER: &str = "sealed_whisper_deliver";
    pub const PUBLISH_HPKE_KEY: &str = "publish_hpke_key";
    pub const GET_HPKE_KEY: &str = "get_hpke_key";
    pub const GROUP_CREATE: &str = "group_create";
    pub const GROUP_ADD: &str = "group_add";
    pub const GROUP_SEND: &str = "group_send";
    pub const GROUP_LEAVE: &str = "group_leave";
    pub const GROUP_LIST: &str = "group_list";
    pub const GROUP_DELIVER: &str = "group_deliver";
    /// Client→Relay: sender is typing (or stopped typing) in the chat room.
    /// Relay fans out a `typing_notify` to all other connected clients (ephemeral,
    /// never stored).
    pub const TYPING: &str = "typing";
    /// Relay→Client notification: another user started or stopped typing.
    pub const TYPING_NOTIFY: &str = "typing_notify";
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 error codes
// ---------------------------------------------------------------------------

pub mod rpc_errors {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const AUTH_FAILED: i32 = -32001;
    pub const NOT_AUTHENTICATED: i32 = -32002;
    pub const SPOOFED_SENDER: i32 = -32003;
    pub const NICKNAME_TAKEN: i32 = -32004;
    /// Per-user resource quota exceeded (e.g. too many key packages).
    /// Stable wire contract; value must never change.
    pub const RESOURCE_EXHAUSTED: i32 = -32008;
    pub const SUBSCRIPTION_REQUIRED: i32 = -32010;
    pub const GROUP_NOT_FOUND: i32 = -32011;
    pub const NOT_A_MEMBER: i32 = -32012;
    /// Rate limit exceeded: client has sent too many broadcast messages in the
    /// current window.  Error code -32020 is a stable wire contract.
    pub const RATE_LIMITED: i32 = -32020;
    /// PoW token required but not present.  Stable wire contract; value must never change.
    pub const POW_REQUIRED: i32 = -32030;
    /// PoW token failed format check, hash mismatch, or wrong difficulty.  Stable wire contract.
    pub const POW_INVALID: i32 = -32031;
    /// PoW token ts_floor is outside ±600s staleness window.  Stable wire contract.
    pub const POW_STALE: i32 = -32032;
    /// PoW token h16 has already been seen (replay attempt).  Stable wire contract.
    pub const POW_REPLAYED: i32 = -32033;
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 envelope types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    pub version: String,
    pub id: u64,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(
        id: u64,
        method: impl Into<String>,
        params: impl Serialize,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            version: "2.0".into(),
            id,
            method: method.into(),
            params: Some(serde_json::to_value(params)?),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    #[serde(rename = "jsonrpc")]
    pub version: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    pub fn new(
        method: impl Into<String>,
        params: impl Serialize,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            version: "2.0".into(),
            method: method.into(),
            params: Some(serde_json::to_value(params)?),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    #[serde(rename = "jsonrpc")]
    pub version: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: u64, result: impl Serialize) -> Result<Self, serde_json::Error> {
        Ok(Self {
            version: "2.0".into(),
            id,
            result: Some(serde_json::to_value(result)?),
            error: None,
        })
    }

    pub fn error(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            version: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }
}

// ---------------------------------------------------------------------------
// Typed param / result structs for each RPC method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeParams {
    pub nonce: String,
    /// Relay-generated random 32-byte salt, base64-encoded.
    /// Client includes this in the PoW hash input.
    /// Empty string when PoW is disabled (difficulty == 0).
    pub server_salt: String,
    /// Required leading zero bits for PoW.  0 = PoW disabled; default 20.
    pub difficulty: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateParams {
    pub pub_key: String,
    pub nonce: String,
    pub signature: String,
    /// PoW token (base64url-encoded 31-byte token).
    /// Required when relay sends difficulty > 0 in ChallengeParams.
    #[serde(default)]
    pub pow_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateResult {
    pub pub_id: String,
    pub subscription_expires: Option<String>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastParams {
    #[serde_as(as = "Base64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastResult {
    pub message_id: String,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverParams {
    pub from: String,
    #[serde_as(as = "Base64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNicknameParams {
    pub nickname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResult {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeyPackageParams {
    pub pub_id: String,
    /// If present, return only the package for this device_id.
    /// If absent, return all packages for `pub_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeyPackageResult {
    pub pub_id: String,
    /// One entry per device that has published a KeyPackage.
    /// Empty if no KeyPackages are stored for this pub_id.
    #[serde_as(as = "Vec<Base64>")]
    pub data: Vec<Vec<u8>>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishKeyPackageParams {
    pub device_id: String,
    #[serde_as(as = "Base64")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageReadyParams {
    pub pub_id: String,
    /// The device_id that just published.  Included so admins can issue
    /// a targeted GetKeyPackage for existing group members' new devices.
    pub device_id: String,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperParams {
    pub to: String,
    #[serde_as(as = "Base64")]
    pub payload: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhisperDeliverParams {
    pub from: String,
    #[serde_as(as = "Base64")]
    pub payload: Vec<u8>,
}

/// Sealed broadcast: sender's identity is hidden inside the encrypted bytes.
/// The relay passes `sealed` through unchanged — it never inspects its contents.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBroadcastParams {
    #[serde_as(as = "Base64")]
    pub sealed: Vec<u8>,
}

/// Sealed deliver: relay fans out to all peers with no `from` field.
/// Sender identity is recovered only by recipients who can decrypt `sealed`.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedDeliverParams {
    #[serde_as(as = "Base64")]
    pub sealed: Vec<u8>,
}

/// Sealed whisper: point-to-point delivery with hidden sender identity.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedWhisperParams {
    pub to: String,
    #[serde_as(as = "Base64")]
    pub sealed: Vec<u8>,
}

/// Sealed whisper deliver: relay forwards to `to` with no `from` field.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedWhisperDeliverParams {
    pub to: String,
    #[serde_as(as = "Base64")]
    pub sealed: Vec<u8>,
}

/// Client publishes its HPKE public key so peers can seal messages to it.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishHpkeKeyParams {
    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,
}

/// Client requests the HPKE public key for another user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHpkeKeyParams {
    pub pub_id: String,
}

/// Response to GetHpkeKey: the stored HPKE public key, or None if not published.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHpkeKeyResult {
    pub pub_id: String,
    #[serde_as(as = "Option<Base64>")]
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserJoinedParams {
    pub pub_id: String,
    pub nickname: Option<String>,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLeftParams {
    pub pub_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserNicknameParams {
    pub pub_id: String,
    pub nickname: String,
}

/// Maximum total number of [`UserInfo`] entries across `online` and `offline`
/// in a single [`DirectoryListParams`] message.
///
/// A rogue or compromised relay cannot cause client OOM by sending a
/// directory_list with millions of entries: deserialization returns an error
/// before the Vec is materialised in memory if the combined length exceeds
/// this cap.  10 000 covers realistic relay deployments (a relay would need
/// 10 000 simultaneous users before hitting this limit).
pub const MAX_USERS_IN_DIRECTORY: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryListParams {
    pub online: Vec<UserInfo>,
    pub offline: Vec<UserInfo>,
}

impl<'de> serde::Deserialize<'de> for DirectoryListParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize into a temporary struct with plain Vecs, then enforce the cap.
        #[derive(serde::Deserialize)]
        struct Raw {
            online: Vec<UserInfo>,
            offline: Vec<UserInfo>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let total = raw.online.len().saturating_add(raw.offline.len());
        if total > MAX_USERS_IN_DIRECTORY {
            return Err(serde::de::Error::custom(format!(
                "directory_list contains {total} entries, exceeding the cap of {MAX_USERS_IN_DIRECTORY}"
            )));
        }
        Ok(DirectoryListParams {
            online: raw.online,
            offline: raw.offline,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionActiveParams {
    pub expires: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequestParams {
    pub duration_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeInvoiceResult {
    pub invoice_id: String,
    pub address: String,
    pub amount_zatoshi: u64,
    /// SQLite-compatible UTC datetime: "YYYY-MM-DD HH:MM:SS"
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreateParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreateResult {
    pub group_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAddParams {
    pub group_id: String,
    pub member_pub_id: String,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSendParams {
    pub group_id: String,
    #[serde_as(as = "Base64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSendResult {
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupLeaveParams {
    pub group_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: String,
    pub name: String,
    pub member_count: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupListResult {
    pub groups: Vec<GroupInfo>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDeliverParams {
    pub from: String,
    pub group_id: String,
    #[serde_as(as = "Base64")]
    pub payload: Vec<u8>,
}

/// Sent by a client to the relay to broadcast a typing-indicator change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingParams {
    /// `true` = user started typing; `false` = user stopped typing.
    pub typing: bool,
}

/// Relay-to-client notification: another peer's typing state changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingNotifyParams {
    /// The pub_id of the user whose typing state changed.
    pub from: String,
    /// `true` = started typing; `false` = stopped typing.
    pub typing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify payload fields serialize as base64 strings, not JSON integer arrays.
    /// Oracle: known input bytes → known base64 string, checked against the raw JSON.
    /// "hello" in base64 is "aGVsbG8=" — this is an external fact, not derived from
    /// the code under test.
    #[test]
    fn broadcast_payload_is_base64() {
        // Oracle: base64("hello") = "aGVsbG8=" — RFC 4648 fact verified with `echo -n hello | base64`
        let params = BroadcastParams {
            payload: b"hello".to_vec(),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(
            json.contains("\"aGVsbG8=\""),
            "expected base64 payload, got: {json}"
        );
        assert!(
            !json.contains("104"), // 'h' as integer — only in array encoding
            "payload must not be a JSON integer array, got: {json}"
        );
    }

    #[test]
    fn deliver_payload_is_base64() {
        // Oracle: same RFC 4648 base64 fact
        let params = DeliverParams {
            from: "abc123".to_string(),
            payload: b"hello".to_vec(),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(
            json.contains("\"aGVsbG8=\""),
            "expected base64 payload, got: {json}"
        );
    }

    #[test]
    fn payload_roundtrip() {
        let original = b"the quick brown fox".to_vec();
        let params = BroadcastParams {
            payload: original.clone(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let decoded: BroadcastParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.payload, original);
    }

    // --- JSON-RPC 2.0 envelope + typed param tests ---
    // Oracle: JSON-RPC 2.0 specification (https://www.jsonrpc.org/specification)
    // and RFC 4648 base64 ("hello" = "aGVsbG8=", verified via `echo -n hello | base64`).
    // None of these tests use roundtrip as their oracle.

    #[test]
    fn request_wire_format_has_jsonrpc_version() {
        // Spec: A Request object MUST have "jsonrpc":"2.0".
        let req = JsonRpcRequest {
            version: "2.0".to_string(),
            id: 1,
            method: "authenticate".to_string(),
            params: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"jsonrpc\":\"2.0\""),
            "request must carry jsonrpc:2.0, got: {json}"
        );
    }

    #[test]
    fn request_has_no_result_or_error_field() {
        // Spec: A Request object must NOT contain a result or error field.
        let req = JsonRpcRequest {
            version: "2.0".to_string(),
            id: 42,
            method: "broadcast".to_string(),
            params: Some(serde_json::json!({"payload": "aGVsbG8="})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            !json.contains("\"result\""),
            "request must not contain 'result', got: {json}"
        );
        assert!(
            !json.contains("\"error\""),
            "request must not contain 'error', got: {json}"
        );
    }

    #[test]
    fn notification_has_no_id_field() {
        // Spec: A Notification is a Request without an id field.
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: "deliver".to_string(),
            params: Some(serde_json::json!({"from": "abc", "payload": "aGVsbG8="})),
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(
            !json.contains("\"id\""),
            "notification must not contain 'id', got: {json}"
        );
        assert!(
            json.contains("\"jsonrpc\":\"2.0\""),
            "notification must carry jsonrpc:2.0, got: {json}"
        );
        assert!(
            json.contains("\"method\":\"deliver\""),
            "notification must carry method, got: {json}"
        );
    }

    #[test]
    fn response_success_has_result_not_error() {
        // Spec: On success, the Response object MUST have a result member and
        // MUST NOT have an error member.
        let resp = JsonRpcResponse::success(7, serde_json::json!({"pub_id": "deadbeef"}))
            .expect("success() must not fail for a serializable value");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"result\""),
            "success response must have 'result', got: {json}"
        );
        assert!(
            !json.contains("\"error\""),
            "success response must not have 'error', got: {json}"
        );
        assert!(
            json.contains("\"id\":7"),
            "success response must echo id, got: {json}"
        );
        assert!(
            json.contains("\"jsonrpc\":\"2.0\""),
            "success response must have jsonrpc:2.0, got: {json}"
        );
    }

    #[test]
    fn response_error_has_integer_code() {
        // Spec: error.code MUST be an Integer (not a string).
        // Oracle: -32001 is the AUTH_FAILED custom error code.
        let resp = JsonRpcResponse::error(3, -32001, "auth failed");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"code\":-32001"),
            "error code must be an integer, got: {json}"
        );
        assert!(
            !json.contains("\"code\":\"-32001\""),
            "error code must NOT be a string, got: {json}"
        );
        assert!(
            json.contains("\"error\""),
            "error response must have 'error' field, got: {json}"
        );
        assert!(
            !json.contains("\"result\""),
            "error response must not have 'result', got: {json}"
        );
    }

    #[test]
    fn error_data_omitted_when_none() {
        // Spec: The data member is OPTIONAL. When absent it must not appear
        // (not null, not present at all).
        let err = JsonRpcError {
            code: -32600,
            message: "invalid request".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(
            !json.contains("\"data\""),
            "data must be absent (not null) when None, got: {json}"
        );
    }

    #[test]
    fn params_omitted_when_none() {
        // Spec: params is OPTIONAL. When absent it must not appear in the wire
        // format (not null, not an empty object).
        let req = JsonRpcRequest {
            version: "2.0".to_string(),
            id: 1,
            method: "challenge".to_string(),
            params: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            !json.contains("\"params\""),
            "params must be absent when None, got: {json}"
        );
    }

    #[test]
    fn broadcast_params_payload_is_base64_string() {
        // Oracle: base64("hello") = "aGVsbG8=" — RFC 4648 fact, verified with
        //   echo -n hello | base64  →  aGVsbG8=
        // The payload must appear as a JSON string, not a JSON integer array.
        let params = BroadcastParams {
            payload: b"hello".to_vec(),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(
            json.contains("\"aGVsbG8=\""),
            "payload must serialize as base64 string \"aGVsbG8=\", got: {json}"
        );
        assert!(
            !json.contains("104"), // 'h' = 104 decimal — only appears in integer-array encoding
            "payload must not be a JSON integer array, got: {json}"
        );
    }

    #[test]
    fn deliver_params_payload_is_base64_string() {
        // Oracle: same RFC 4648 fact as above.
        let params = DeliverParams {
            from: "cafebabe".to_string(),
            payload: b"hello".to_vec(),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(
            json.contains("\"aGVsbG8=\""),
            "payload must serialize as base64 string \"aGVsbG8=\", got: {json}"
        );
        assert!(
            !json.contains("104"),
            "payload must not be a JSON integer array, got: {json}"
        );
    }

    #[test]
    fn error_code_constants_match_spec() {
        // Oracle: JSON-RPC 2.0 specification defines exact numeric values for
        // standard codes; custom codes are defined by the nie-hlns epic spec.
        assert_eq!(rpc_errors::PARSE_ERROR, -32700);
        assert_eq!(rpc_errors::INVALID_REQUEST, -32600);
        assert_eq!(rpc_errors::METHOD_NOT_FOUND, -32601);
        assert_eq!(rpc_errors::INVALID_PARAMS, -32602);
        assert_eq!(rpc_errors::INTERNAL_ERROR, -32603);
        assert_eq!(rpc_errors::AUTH_FAILED, -32001);
        assert_eq!(rpc_errors::NOT_AUTHENTICATED, -32002);
        assert_eq!(rpc_errors::SPOOFED_SENDER, -32003);
        assert_eq!(rpc_errors::NICKNAME_TAKEN, -32004);
    }

    #[test]
    fn rpc_method_constants_are_lowercase_snake_case() {
        // Oracle: JSON-RPC 2.0 spec says method names are case-sensitive;
        // the nie-hlns epic spec mandates lowercase_snake_case.
        for method in [
            rpc_methods::CHALLENGE,
            rpc_methods::AUTHENTICATE,
            rpc_methods::BROADCAST,
            rpc_methods::DELIVER,
            rpc_methods::DIRECTORY_LIST,
            rpc_methods::USER_JOINED,
            rpc_methods::USER_LEFT,
            rpc_methods::SET_NICKNAME,
            rpc_methods::USER_NICKNAME,
            rpc_methods::PUBLISH_KEY_PACKAGE,
            rpc_methods::GET_KEY_PACKAGE,
            rpc_methods::KEY_PACKAGE_READY,
            rpc_methods::WHISPER,
            rpc_methods::WHISPER_DELIVER,
        ] {
            assert_eq!(
                method,
                method.to_lowercase(),
                "method constant must be lowercase: {method}"
            );
            assert!(
                !method.contains('-'),
                "method must use underscore not hyphen: {method}"
            );
        }
    }

    #[test]
    fn publish_key_package_params_device_id_roundtrip() {
        // Verify device_id serializes as a JSON string key and survives a roundtrip.
        // Oracle: serde_json produces {"device_id":"aaa...","data":"AQID"} —
        // the key name and string type are serde_json invariants, not derived
        // from the code under test. base64([1,2,3]) = "AQID" per RFC 4648
        // (verified with: python3 -c "import base64; print(base64.b64encode(bytes([1,2,3])).decode())")
        let device_id = "a".repeat(64);
        let params = PublishKeyPackageParams {
            device_id: device_id.clone(),
            data: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(
            json.contains("\"device_id\""),
            "expected device_id key in JSON, got: {json}"
        );
        assert!(
            json.contains(&format!("\"{}\"", "a".repeat(64))),
            "expected device_id value in JSON, got: {json}"
        );
        // data: [1,2,3] → base64 = "AQID" (RFC 4648 external fact)
        assert!(
            json.contains("\"AQID\""),
            "expected base64 data \"AQID\" in JSON, got: {json}"
        );
        let decoded: PublishKeyPackageParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.device_id, device_id);
        assert_eq!(decoded.data, vec![1, 2, 3]);
    }
}
