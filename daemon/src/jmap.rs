// JMAP Core HTTP layer (RFC 8620) + urn:ietf:params:jmap:chat transport.
//
// Endpoints:
//   GET  /.well-known/jmap          → Session object (RFC 8620 §2)
//   POST /jmap                      → Batch method call (RFC 8620 §3)
//   GET  /jmap/eventsource/         → Server-Sent Events push (RFC 8620 §7.3)
//
// All JMAP endpoints require the same Bearer token as /api/*.
// EventSource additionally accepts ?token= for browser EventSource API.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{sse, IntoResponse},
    Json,
};
use nie_core::messages::{pad, ClearMessage};
use nie_core::protocol::{rpc_methods, BroadcastParams, JsonRpcRequest, TypingParams};
use nie_core::transport::next_request_id;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

use ulid::Ulid;

use crate::state::DaemonState;
use crate::store::{ChatContactRow, ChatRow, EditBodyResult, MessageRow, SpaceMemberOp, SpaceRole};
use crate::token::validate_token_header;
use crate::types::DaemonEvent;

// ── Capability URIs ────────────────────────────────────────────────────────────

pub const CAP_CORE: &str = "urn:ietf:params:jmap:core";
pub const CAP_CHAT: &str = "urn:ietf:params:jmap:chat";

/// RFC 8620 §3.1: maximum number of method calls allowed in a single
/// POST /jmap batch.  Exceeding this returns a 400 requestTooLarge response.
const MAX_CALLS_IN_REQUEST: usize = 64;

// ── Session object (RFC 8620 §2) ───────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    #[serde(rename = "@type")]
    type_tag: &'static str,
    capabilities: HashMap<String, Value>,
    accounts: HashMap<String, AccountInfo>,
    primary_accounts: HashMap<String, String>,
    username: String,
    api_url: String,
    upload_url: String,
    download_url: String,
    event_source_url: String,
    state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    name: String,
    is_personal: bool,
    is_read_only: bool,
    account_capabilities: HashMap<String, Value>,
}

// ── JMAP request/response types (RFC 8620 §3) ─────────────────────────────────

/// Incoming POST /jmap body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JmapRequest {
    #[allow(dead_code)]
    using: Vec<String>,
    method_calls: Vec<MethodCall>,
    // created_ids omitted — not used in daemon v0
}

/// A single method call: [method, arguments, callId]
#[derive(Deserialize)]
pub struct MethodCall(pub String, pub Value, pub String);

/// A single method response: [method, result, callId]
#[derive(Serialize)]
pub struct MethodResponse(pub String, pub Value, pub String);

/// Outgoing POST /jmap body.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JmapResponse {
    session_state: String,
    method_responses: Vec<MethodResponse>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /.well-known/jmap — return the Session object.
pub async fn handle_jmap_session(
    State(state): State<DaemonState>,
) -> Result<Json<Session>, StatusCode> {
    let session = build_session(&state).await?;
    Ok(Json(session))
}

/// POST /jmap — dispatch a batch of JMAP method calls.
pub async fn handle_jmap_request(
    State(state): State<DaemonState>,
    Json(req): Json<JmapRequest>,
) -> Result<Json<JmapResponse>, StatusCode> {
    // RFC 8620 §3.1: reject batches exceeding the advertised limit.
    // The spec calls for a 400 with a problem+json body; StatusCode::BAD_REQUEST
    // gives the correct status (body omitted — acceptable for a local server).
    if req.method_calls.len() > MAX_CALLS_IN_REQUEST {
        return Err(StatusCode::BAD_REQUEST);
    }

    let session_state = session_state_token(&state).await?;

    let mut method_responses = Vec::with_capacity(req.method_calls.len());
    for MethodCall(method, args, call_id) in req.method_calls {
        let response = dispatch_method(&method, args, &call_id, &state).await;
        method_responses.push(MethodResponse(response.0, response.1, call_id));
    }

    Ok(Json(JmapResponse {
        session_state,
        method_responses,
    }))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async fn build_session(state: &DaemonState) -> Result<Session, StatusCode> {
    let account_id = state.my_pub_id().to_string();
    let display_name = state
        .display_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if account_id.len() >= 8 {
                format!("{}…", &account_id[..8])
            } else {
                account_id.clone()
            }
        });

    let session_state = session_state_token(state).await?;

    // Session-level capabilities. urn:ietf:params:jmap:chat value is {} per spec.
    let mut caps: HashMap<String, Value> = HashMap::new();
    caps.insert(
        CAP_CORE.to_string(),
        serde_json::json!({ "maxCallsInRequest": MAX_CALLS_IN_REQUEST }),
    );
    caps.insert(CAP_CHAT.to_string(), serde_json::json!({}));

    // Account-level capabilities carry the Chat-specific fields.
    let mut acct_caps: HashMap<String, Value> = HashMap::new();
    acct_caps.insert(
        CAP_CHAT.to_string(),
        serde_json::json!({
            "supportedBodyTypes": ["text/plain"]
        }),
    );

    let acct_info = AccountInfo {
        name: display_name,
        is_personal: true,
        is_read_only: false,
        account_capabilities: acct_caps,
    };
    let mut accounts = HashMap::new();
    accounts.insert(account_id.clone(), acct_info);

    let mut primary_accounts = HashMap::new();
    primary_accounts.insert(CAP_CHAT.to_string(), account_id.clone());

    // URL templates — use the listen address if available; fall back to a
    // relative-URL convention clients can resolve against the origin.
    let base =
        std::env::var("JMAP_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:7734".to_string());

    Ok(Session {
        type_tag: "Session",
        capabilities: caps,
        accounts,
        primary_accounts,
        username: account_id,
        api_url: format!("{base}/jmap"),
        upload_url: format!("{base}/jmap/upload/{{accountId}}/"),
        download_url: format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}"),
        event_source_url: format!(
            "{base}/jmap/eventsource/?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"
        ),
        state: session_state,
    })
}

/// Aggregate state token: concatenate per-type tokens to detect any change.
///
/// All 7 reads execute inside a single SQLite read transaction (nie-zvzr) so
/// the composite token reflects a consistent snapshot even if a concurrent
/// writer commits between reads.
async fn session_state_token(state: &DaemonState) -> Result<String, StatusCode> {
    let Some(store) = state.store() else {
        // No store → stable token.
        return Ok("0".to_string());
    };
    let parts = store
        .state_token_snapshot(&[
            "ChatContact",
            "Chat",
            "Message",
            "Space",
            "SpaceMember",
            "SpaceInvite",
            "Category",
        ])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(parts.join(":"))
}

/// Dispatch a single JMAP method call.  Returns (method_name, result_value).
/// Unknown methods return the standard JMAP `error/unknownMethod` response.
pub(crate) async fn dispatch_method(
    method: &str,
    args: Value,
    call_id: &str,
    state: &DaemonState,
) -> (String, Value) {
    let result = match method {
        "ChatContact/get" => contact_get(args, state).await,
        "ChatContact/changes" => contact_changes(args, state).await,
        "ChatContact/set" => contact_set(args, state).await,
        "ChatContact/query" => contact_query(args, state).await,
        "ChatContact/queryChanges" => contact_query_changes(args, state).await,
        "Chat/get" => chat_get(args, state).await,
        "Chat/changes" => chat_changes(args, state).await,
        "Chat/query" => chat_query(args, state).await,
        "Chat/typing" => chat_typing(args, state).await,
        "Space/get" => space_get(args, state).await,
        "Space/changes" => space_changes(args, state).await,
        "Space/set" => space_set(args, state).await,
        "Space/query" => space_query(args, state).await,
        "Space/queryChanges" => space_query_changes(args, state).await,
        "Space/join" => space_join(args, state).await,
        "SpaceInvite/get" => space_invite_get(args, state).await,
        "SpaceInvite/set" => space_invite_set(args, state).await,
        "Message/get" => message_get(args, state).await,
        "Message/changes" => message_changes(args, state).await,
        "Message/set" => message_set(args, state).await,
        "Message/query" => message_query(args, state).await,
        "Message/queryChanges" => message_query_changes(args, state).await,
        _ => {
            tracing::debug!("JMAP unknownMethod: {} (callId={})", method, call_id);
            return (
                "error".to_string(),
                serde_json::json!({ "type": "unknownMethod" }),
            );
        }
    };
    result
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

/// Validate the accountId argument against the daemon's own pub_id.
/// Returns Ok(account_id) or Err(error_response).
fn validate_account_id(args: &Value, state: &DaemonState) -> Result<String, (String, Value)> {
    let account_id = args
        .get("accountId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| state.my_pub_id().to_string());
    if account_id != state.my_pub_id() {
        return Err((
            "error".to_string(),
            serde_json::json!({ "type": "accountNotFound" }),
        ));
    }
    Ok(account_id)
}

fn method_ok(name: &str, result: Value) -> (String, Value) {
    (name.to_string(), result)
}

fn method_error(error_type: &str) -> (String, Value) {
    (
        "error".to_string(),
        serde_json::json!({ "type": error_type }),
    )
}

fn invalid_args(description: &str) -> (String, Value) {
    (
        "error".to_string(),
        serde_json::json!({ "type": "invalidArguments", "description": description }),
    )
}

fn server_fail(msg: &str) -> (String, Value) {
    tracing::warn!("JMAP serverFail: {msg}");
    (
        "error".to_string(),
        serde_json::json!({ "type": "serverFail", "description": msg }),
    )
}

/// Log a database error internally and return a generic serverFail response.
/// Never exposes raw SQLite error strings (table/column names) to the client.
fn db_error(e: impl std::fmt::Display) -> (String, Value) {
    tracing::error!("database error: {e}");
    server_fail("database error")
}

fn contact_to_json(c: &ChatContactRow) -> Value {
    serde_json::json!({
        "id": c.id,
        "login": c.login,
        "displayName": c.display_name,
        "firstSeenAt": c.first_seen_at,
        "lastSeenAt": c.last_seen_at,
        "presence": c.presence,
        "blocked": c.blocked,
    })
}

fn chat_to_json(c: &ChatRow) -> Value {
    serde_json::json!({
        "id": c.id,
        "kind": c.kind,
        "name": c.name,
        "spaceId": c.space_id,
        "contactId": c.contact_id,
        "createdAt": c.created_at,
        "lastMessageAt": c.last_message_at,
        "unreadCount": c.unread_count,
        "muted": c.muted,
    })
}

fn message_to_json(m: &MessageRow) -> Value {
    let reactions: Value =
        serde_json::from_str(&m.reactions).unwrap_or(Value::Object(Default::default()));
    let edit_history: Value = serde_json::from_str(&m.edit_history).unwrap_or(Value::Array(vec![]));
    serde_json::json!({
        "id": m.id,
        "chatId": m.chat_id,
        "senderId": m.sender_id,
        "body": m.body,
        "bodyType": m.body_type,
        "sentAt": m.sent_at,
        "receivedAt": m.received_at,
        "deliveryState": m.delivery_state,
        "deletedAt": m.deleted_at,
        "deletedForAll": m.deleted_for_all,
        "reactions": reactions,
        "editHistory": edit_history,
        "replyTo": m.reply_to,
        "threadRootId": m.thread_root_id,
        "expiresAt": m.expires_at,
        "burnOnRead": m.burn_on_read,
        "readAt": m.read_at,
    })
}

/// Display name canonicalization — must match relay/src/ws.rs:canonicalize_display_name.
/// 1. NFC-normalize.  2. Reject bidi controls.  3. Strip zero-width chars.
/// 4. Trim whitespace.  5. Reject if empty or longer than 32 Unicode scalars.
fn canonicalize_display_name(s: &str) -> Result<String, &'static str> {
    const BIDI_CONTROLS: &[char] = &[
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}',
    ];
    const ZERO_WIDTH: &[char] = &['\u{200B}', '\u{200C}', '\u{2060}', '\u{FEFF}'];
    let normalized: String = s.nfc().collect();
    if normalized.chars().any(|c| BIDI_CONTROLS.contains(&c)) {
        return Err("contains bidirectional control characters");
    }
    let stripped: String = normalized
        .chars()
        .filter(|c| !ZERO_WIDTH.contains(c))
        .collect();
    let trimmed = stripped.trim().to_string();
    if trimmed.is_empty() {
        return Err("empty after canonicalization");
    }
    if trimmed.chars().count() > 32 {
        return Err("display name too long");
    }
    Ok(trimmed)
}

// ── ChatContact/* handlers (nie-c3cq) ─────────────────────────────────────────

async fn contact_get(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };

    // Parse ids field: null or absent → return all; array → specific ids
    let ids_opt: Option<Vec<String>> = match args.get("ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        ),
        _ => return method_error("invalidArguments"),
    };
    if let Some(ref ids) = ids_opt {
        if ids.len() > 4096 {
            return invalid_args("too many ids");
        }
    }
    let id_strs: Option<Vec<&str>> = ids_opt
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());

    let state_tok = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    match store.get_contacts(id_strs.as_deref()).await {
        Ok((list, not_found)) => method_ok(
            "ChatContact/get",
            serde_json::json!({
                "accountId": account_id,
                "state": state_tok,
                "list": list.iter().map(contact_to_json).collect::<Vec<_>>(),
                "notFound": not_found,
            }),
        ),
        Err(e) => db_error(e),
    }
}

async fn contact_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let since_state = args
        .get("sinceState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    if since_state != new_state {
        // The daemon has no per-object change log, so it cannot enumerate
        // which contacts were created, updated, or removed since sinceState.
        // Return cannotCalculateChanges per RFC 8620 §5.2; clients must fall
        // back to ChatContact/get with ids=null to refresh their cache.
        return (
            "error".to_string(),
            serde_json::json!({"type": "cannotCalculateChanges", "newState": new_state}),
        );
    }
    method_ok(
        "ChatContact/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since_state,
            "newState": new_state,
            "hasMoreChanges": false,
            "removed": [],
            "created": [],
            "updated": [],
        }),
    )
}

async fn contact_set(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let old_state = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    let mut updated: HashMap<String, Value> = HashMap::new();
    let mut not_updated: HashMap<String, Value> = HashMap::new();

    if let Some(Value::Object(updates)) = args.get("update") {
        for (id, patch) in updates {
            // ── Phase 1 (validate + collect, no writes) ───────────────────────
            // All validation happens before any store write.  This ensures RFC
            // 8620 §7.1 atomicity for input errors: a bad displayName type or
            // an unrecognized key rejects the whole patch with no side effects.

            // A non-Object patch is structurally invalid.
            if !patch.is_object() {
                not_updated.insert(
                    id.clone(),
                    serde_json::json!({
                        "type": "invalidArguments",
                        "description": "patch must be a JSON object"
                    }),
                );
                continue;
            }

            let mut blocked: Option<bool> = None;
            let mut display_name: Option<Option<String>> = None;
            let mut phase1_err: Option<Value> = None;

            if let Some(blocked_val) = patch.get("blocked") {
                match blocked_val.as_bool() {
                    Some(b) => blocked = Some(b),
                    None => {
                        phase1_err = Some(serde_json::json!({
                            "type": "invalidProperties",
                            "properties": ["blocked"]
                        }));
                    }
                }
            }
            if phase1_err.is_none() {
                if let Some(name_val) = patch.get("displayName") {
                    if name_val.is_null() {
                        display_name = Some(None);
                    } else if let Some(s) = name_val.as_str() {
                        match canonicalize_display_name(s) {
                            Ok(n) => display_name = Some(Some(n)),
                            Err(msg) => {
                                phase1_err = Some(serde_json::json!({
                                    "type": "invalidProperties",
                                    "properties": ["displayName"],
                                    "description": msg
                                }));
                            }
                        }
                    } else {
                        phase1_err = Some(serde_json::json!({
                            "type": "invalidProperties",
                            "properties": ["displayName"]
                        }));
                    }
                }
            }
            // Reject any unrecognized patch keys.  RFC 8620 §7.1 SHOULD return
            // invalidProperties for unknown properties; also ensures mixed patches
            // ({blocked:true, unknownField:"x"}) don't silently drop the unknown key.
            if phase1_err.is_none() {
                // patch.is_object() was checked and would have continued if false.
                let unknown: Vec<&str> = patch
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|k| !matches!(k.as_str(), "blocked" | "displayName"))
                    .map(String::as_str)
                    .collect();
                if !unknown.is_empty() {
                    phase1_err = Some(serde_json::json!({
                        "type": "invalidProperties",
                        "properties": unknown,
                        "description": "unrecognized patch properties"
                    }));
                }
            }

            if let Some(err) = phase1_err {
                not_updated.insert(id.clone(), err);
                continue;
            }

            // ── Phase 2a: empty patch — existence check only ──────────────────
            if blocked.is_none() && display_name.is_none() {
                // Phase 1 passed with no fields set: patch was {} (empty object).
                // RFC 8620 §7.1: empty patch is a no-op if the object exists.
                let (_, not_found) = match store.get_contacts(Some(&[id.as_str()])).await {
                    Ok(r) => r,
                    Err(e) => return db_error(e),
                };
                if not_found.is_empty() {
                    updated.insert(id.clone(), Value::Null);
                } else {
                    not_updated.insert(id.clone(), serde_json::json!({"type": "notFound"}));
                }
                continue;
            }

            // ── Phase 2b: apply fields atomically ────────────────────────────
            // update_contact_fully wraps all writes in a single SQLite transaction.
            // This ensures a multi-field patch ({blocked, displayName}) is visible
            // atomically — no concurrent reader sees an intermediate state —
            // and emits a single ChatContact state-token bump.
            match store
                .update_contact_fully(id, blocked, display_name.as_ref().map(|o| o.as_deref()))
                .await
            {
                Ok(true) => {
                    updated.insert(id.clone(), Value::Null);
                }
                Ok(false) => {
                    not_updated.insert(id.clone(), serde_json::json!({"type": "notFound"}));
                }
                Err(e) => return db_error(e),
            }
        }
    }

    // create and destroy are not supported for ChatContact
    let mut not_created: HashMap<String, Value> = HashMap::new();
    if let Some(Value::Object(creates)) = args.get("create") {
        for (cid, _) in creates {
            not_created.insert(
                cid.clone(),
                serde_json::json!({"type":"forbidden","description":"ChatContact records are auto-created"}),
            );
        }
    }

    let new_state = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    method_ok(
        "ChatContact/set",
        serde_json::json!({
            "accountId": account_id,
            "oldState": old_state,
            "newState": new_state,
            "created": {},
            "updated": updated,
            "destroyed": [],
            "notCreated": not_created,
            "notUpdated": not_updated,
            "notDestroyed": {},
        }),
    )
}

async fn contact_query(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };

    let filter = args.get("filter");
    let presence = filter
        .and_then(|f| f.get("presence"))
        .and_then(|v| v.as_str());
    let blocked = filter
        .and_then(|f| f.get("blocked"))
        .and_then(|v| v.as_bool());

    let query_state = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    let ids = match store.query_contacts(presence, blocked).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    let total = ids.len() as i64;

    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(total);
    // RFC 8620 §5.1: position and limit must be non-negative integers.
    // Negative values wrap on the as-usize cast and panic in slice indexing.
    // Saturating addition prevents a second panic class: two large-but-valid
    // i64 values (e.g. position=i64::MAX-1, limit=2) overflow i64 before the
    // .min() clamp can save them; saturating_add clamps to i64::MAX instead.
    if position < 0 {
        return invalid_args("position must be non-negative");
    }
    if limit < 0 {
        return invalid_args("limit must be non-negative");
    }
    let start = (position as usize).min(ids.len());
    let end = (position.saturating_add(limit) as usize).min(ids.len());
    let page_ids = &ids[start..end];

    method_ok(
        "ChatContact/query",
        serde_json::json!({
            "accountId": account_id,
            "queryState": query_state,
            "canCalculateChanges": false,
            "position": position,
            "ids": page_ids,
            "total": total,
        }),
    )
}

async fn contact_query_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let since = args
        .get("sinceQueryState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    if since != new_state {
        // The daemon has no per-object change log.  ChatContact/query already
        // advertises canCalculateChanges:false; returning cannotCalculateChanges
        // here is the correct RFC 8620 §5.4 response when clients call anyway.
        return (
            "error".to_string(),
            serde_json::json!({"type": "cannotCalculateChanges", "newState": new_state}),
        );
    }
    // State unchanged — return empty result with current total.
    let filter = args.get("filter");
    let presence = filter
        .and_then(|f| f.get("presence"))
        .and_then(|v| v.as_str());
    let blocked = filter
        .and_then(|f| f.get("blocked"))
        .and_then(|v| v.as_bool());
    let ids = match store.query_contacts(presence, blocked).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    let total = ids.len() as i64;
    method_ok(
        "ChatContact/queryChanges",
        serde_json::json!({
            "accountId": account_id,
            "oldQueryState": since,
            "newQueryState": new_state,
            "removed": [],
            "added": [],
            "total": total,
        }),
    )
}

// ── Chat/* handlers (nie-ib2s) ─────────────────────────────────────────────────

async fn chat_get(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let ids_opt: Option<Vec<String>> = match args.get("ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        ),
        _ => return method_error("invalidArguments"),
    };
    let id_strs: Option<Vec<&str>> = ids_opt
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());
    let state_tok = match store.state_token("Chat").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    match store.get_chats(id_strs.as_deref()).await {
        Ok((list, not_found)) => method_ok(
            "Chat/get",
            serde_json::json!({
                "accountId": account_id,
                "state": state_tok,
                "list": list.iter().map(chat_to_json).collect::<Vec<_>>(),
                "notFound": not_found,
            }),
        ),
        Err(e) => db_error(e),
    }
}

async fn chat_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let since_state = args
        .get("sinceState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("Chat").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    if since_state != new_state {
        // The daemon has no per-object change log, so it cannot enumerate
        // which chats were created, updated, or removed since sinceState.
        // Return cannotCalculateChanges per RFC 8620 §5.2; clients must fall
        // back to Chat/get with ids=null to refresh their cache.
        return (
            "error".to_string(),
            serde_json::json!({"type": "cannotCalculateChanges", "newState": new_state}),
        );
    }
    method_ok(
        "Chat/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since_state,
            "newState": new_state,
            "hasMoreChanges": false,
            "removed": [],
            "created": [],
            "updated": [],
        }),
    )
}

async fn chat_query(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let query_state = match store.state_token("Chat").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    let (all_chats, _) = match store.get_chats(None).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    // Optional kind filter
    let kind_filter = args
        .get("filter")
        .and_then(|f| f.get("kind"))
        .and_then(|v| v.as_str());
    let ids: Vec<String> = all_chats
        .iter()
        .filter(|c| kind_filter.is_none_or(|k| c.kind == k))
        .map(|c| c.id.clone())
        .collect();
    let total = ids.len() as i64;
    method_ok(
        "Chat/query",
        serde_json::json!({
            "accountId": account_id,
            "queryState": query_state,
            "canCalculateChanges": false,
            "position": 0,
            "ids": ids,
            "total": total,
        }),
    )
}

// ── Chat/typing handler ────────────────────────────────────────────────────────

/// Chat/typing — send a typing indicator to the relay.
///
/// Arguments: `{ "accountId": "...", "chatId": "...", "typing": true|false }`.
/// Forwards a `typing` JSON-RPC request to the relay (fire-and-forget); returns
/// `["Chat/typing/reply", {}, callId]` to the caller.
async fn chat_typing(args: Value, state: &DaemonState) -> (String, Value) {
    if let Err(e) = validate_account_id(&args, state) {
        return e;
    }
    let typing = args
        .get("typing")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if let Some(tx) = state.relay_tx().await {
        match JsonRpcRequest::new(
            nie_core::transport::next_request_id(),
            rpc_methods::TYPING,
            TypingParams { typing },
        ) {
            Ok(req) => {
                let _ = tx.send(req).await;
            }
            Err(e) => {
                tracing::warn!("Chat/typing: failed to build request: {e}");
            }
        }
    }

    method_ok("Chat/typing", serde_json::json!({}))
}

// ── Space/* handlers (nie-7ew5) ───────────────────────────────────────────────

fn space_to_json(s: &crate::store::SpaceRow, members: &[crate::store::SpaceMemberRow]) -> Value {
    let member_list: Vec<Value> = members
        .iter()
        .map(|m| {
            serde_json::json!({
                "contactId": m.contact_id,
                "role": m.role,
                "nick": m.nick,
                "joinedAt": m.joined_at,
            })
        })
        .collect();
    serde_json::json!({
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "createdAt": s.created_at,
        "memberList": member_list,
    })
}

async fn space_get(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let ids_opt: Option<Vec<String>> = match args.get("ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        ),
        _ => return method_error("invalidArguments"),
    };
    let id_strs: Option<Vec<&str>> = ids_opt
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());
    let state_tok = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    let (spaces, not_found) = match store.get_spaces(id_strs.as_deref(), &account_id).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    // Fetch all member rows for every returned space in a single IN query
    // rather than one query per space (N+1).
    let space_id_strs: Vec<&str> = spaces.iter().map(|s| s.id.as_str()).collect();
    let mut members_by_space = match store.get_space_members_batch(&space_id_strs).await {
        Ok(m) => m,
        Err(e) => return db_error(e),
    };
    let mut list = Vec::new();
    for s in &spaces {
        let members = members_by_space.remove(&s.id).unwrap_or_default();
        list.push(space_to_json(s, &members));
    }
    method_ok(
        "Space/get",
        serde_json::json!({
            "accountId": account_id,
            "state": state_tok,
            "list": list,
            "notFound": not_found,
        }),
    )
}

async fn space_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let since = args
        .get("sinceState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    if since != new_state {
        // The daemon has no per-object change log, so it cannot enumerate
        // which spaces were created, updated, or destroyed since sinceState.
        // Return cannotCalculateChanges per RFC 8620 §5.2; clients must fall
        // back to Space/get with ids=null to refresh their cache.
        return (
            "error".to_string(),
            serde_json::json!({"type": "cannotCalculateChanges", "newState": new_state}),
        );
    }
    method_ok(
        "Space/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since,
            "newState": new_state,
            "hasMoreChanges": false,
            "created": [],
            "updated": [],
            "destroyed": [],
        }),
    )
}

// SpaceRole in store.rs is the single source of truth for valid role values.

/// A validated, parsed simple-space-property update ready to pass to Phase 2.
///
/// Adding a new simple Space property requires:
///   1. Adding a variant here.
///   2. Adding an arm to `try_parse_simple_space_prop`.
///
/// The Phase 2 `match op {}` in `space_set` is exhaustive, so the compiler
/// flags a missing arm at build time.  The `try_parse_simple_space_prop` match
/// is also exhaustive — no separate routing predicate needed.
enum SimplePropPatch<'a> {
    Name(&'a str),
    /// `None` = null value → clears the description field.
    Description(Option<&'a str>),
}

/// Try to parse a patch path as a simple space property.
///
/// Returns `None` if the path is not a simple space property (caller should
/// try member-patch parsing instead).  Returns `Some(Ok(op))` on success or
/// `Some(Err(json_error))` if the path is recognised but the value has the
/// wrong type.
///
/// When adding a new simple Space property, add a variant to `SimplePropPatch`
/// and a match arm here.  The compiler enforces exhaustiveness on the Phase 2
/// `match op {}` over `SimplePropPatch`; it does not enforce completeness here
/// (string matches cannot be exhaustive).  The prose doc is the contract.
fn try_parse_simple_space_prop<'a>(
    path: &str,
    value: &'a Value,
) -> Option<Result<SimplePropPatch<'a>, Value>> {
    match path {
        "name" => {
            // name must be a non-null string.
            let result = value.as_str().map(SimplePropPatch::Name).ok_or_else(|| {
                serde_json::json!({
                    "type": "invalidProperties",
                    "properties": ["name"],
                    "description": "name must be a string"
                })
            });
            Some(result)
        }
        "description" => {
            // description may be null (to clear it) or a string.
            if value.is_null() {
                Some(Ok(SimplePropPatch::Description(None)))
            } else {
                let result = value
                    .as_str()
                    .ok_or_else(|| {
                        serde_json::json!({
                            "type": "invalidProperties",
                            "properties": ["description"],
                            "description": "description must be a string or null"
                        })
                    })
                    .and_then(|s| {
                        // nie-0j6b.10: cap description at 1024 bytes.
                        if s.len() > 1024 {
                            Err(serde_json::json!({
                                "type": "invalidArguments",
                                "properties": ["description"],
                                "description": "description exceeds maximum length of 1024 bytes"
                            }))
                        } else {
                            Ok(SimplePropPatch::Description(Some(s)))
                        }
                    });
                Some(result)
            }
        }
        _ => None, // not a simple space property; caller tries member-patch next
    }
}

/// Validate a member patch path and value without touching the store.
///
/// Called in a first pass over the patch map so that input errors are caught
/// before any property is written.  This preserves RFC 8620 §7.1 atomicity
/// for the common case: if the patch contains both a valid `name` and an
/// invalid `members/*` path, neither write should happen and `notUpdated`
/// must be returned without any side effects.
///
/// Returns `Ok(())` for a recognised path with a valid value, or
/// `Err(json_error)` for an unrecognised path or an invalid role.
fn validate_member_patch(path: &str, value: &Value) -> Result<(), Value> {
    let Some(member_id) = path.strip_prefix("members/") else {
        return Err(serde_json::json!({
            "type": "invalidPatch",
            "description": format!("unrecognized patch path: {path}")
        }));
    };
    // "members/" with no contact id is not a valid patch path.
    if member_id.is_empty() {
        return Err(serde_json::json!({
            "type": "invalidPatch",
            "description": "members/ patch path requires a non-empty contact id"
        }));
    }
    if !value.is_null() {
        // A non-null member patch value must be an object.  Without this check,
        // a scalar value (e.g. 42) passes validation because value.get("role")
        // returns None on non-objects, silently defaulting to SpaceRole::Member.
        if !value.is_object() {
            return Err(serde_json::json!({
                "type": "invalidArguments",
                "description": "member patch value must be null (to remove) or an object"
            }));
        }
        match value.get("role") {
            None => {} // absent → default (member); validated at parse time in Phase 2
            // Present but not a string (e.g. {"role": 42}) — reject explicitly
            // rather than silently coercing to the default.
            Some(v) => {
                let s = v.as_str().ok_or_else(|| {
                    serde_json::json!({
                        "type": "invalidArguments",
                        "description": "role must be a string"
                    })
                })?;
                // SpaceRole::parse is the single source of truth for valid roles.
                if SpaceRole::parse(s).is_none() {
                    return Err(serde_json::json!({
                        "type": "invalidArguments",
                        "description": format!(
                            "role must be one of: {}",
                            SpaceRole::all().iter().map(|r| r.as_str()).collect::<Vec<_>>().join(", ")
                        )
                    }));
                }
            }
        }
    }
    Ok(())
}

async fn space_set(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let old_state = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut destroyed: Vec<Value> = Vec::new();
    let mut not_destroyed = serde_json::Map::new();

    // ── create ────────────────────────────────────────────────────────────
    if let Some(Value::Object(creates)) = args.get("create") {
        for (client_id, props) in creates {
            let name = match props.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["name"]}),
                    );
                    continue;
                }
            };
            let name = match canonicalize_display_name(name) {
                Ok(n) => n,
                Err(_) => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({
                            "type": "invalidProperties",
                            "properties": ["name"],
                            "description": "display name invalid"
                        }),
                    );
                    continue;
                }
            };
            // description is optional: absent or null → no description.
            // A non-null, non-string value is invalid — reject rather than
            // silently dropping it (inconsistent with the update path which
            // rejects wrong-type description with invalidProperties).
            let description = match props.get("description") {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_str() {
                    Some(s) => {
                        // nie-0j6b.10: cap description at 1024 bytes.
                        if s.len() > 1024 {
                            not_created.insert(
                                client_id.clone(),
                                serde_json::json!({
                                    "type": "invalidArguments",
                                    "properties": ["description"],
                                    "description": "description exceeds maximum length of 1024 bytes"
                                }),
                            );
                            continue;
                        }
                        Some(s.to_string())
                    }
                    None => {
                        not_created.insert(
                            client_id.clone(),
                            serde_json::json!({
                                "type": "invalidProperties",
                                "properties": ["description"],
                                "description": "description must be a string or null"
                            }),
                        );
                        continue;
                    }
                },
            };
            let id = crate::store::Store::new_id();
            match store
                .create_space_full(&id, &name, description.as_deref(), &account_id)
                .await
            {
                Ok(()) => {
                    created.insert(client_id.clone(), serde_json::json!({ "id": id }));
                }
                Err(e) => {
                    not_created.insert(client_id.clone(), {
                        tracing::error!("database error: {e}");
                        serde_json::json!({"type":"serverFail","description":"database error"})
                    });
                }
            }
        }
    }

    // ── update (patch) ────────────────────────────────────────────────────
    if let Some(Value::Object(updates)) = args.get("update") {
        for (space_id, patch) in updates {
            if let Value::Object(patch_map) = patch {
                // Single query: check existence and role atomically to avoid
                // a TOCTOU gap between separate space_exists / get_space_member_role
                // calls that could leak space existence via the forbidden path.
                match store.get_space_role_if_exists(space_id, &account_id).await {
                    Err(e) => {
                        not_updated.insert(space_id.clone(), {
                            tracing::error!("database error: {e}");
                            serde_json::json!({"type":"serverFail","description":"database error"})
                        });
                        continue;
                    }
                    Ok(None) => {
                        not_updated
                            .insert(space_id.clone(), serde_json::json!({"type": "notFound"}));
                        continue;
                    }
                    Ok(Some(None)) => {
                        // Space exists but caller is not a member.
                        not_updated
                            .insert(space_id.clone(), serde_json::json!({"type": "forbidden"}));
                        continue;
                    }
                    Ok(Some(Some(role))) if role != crate::store::SpaceRole::Admin => {
                        not_updated
                            .insert(space_id.clone(), serde_json::json!({"type": "forbidden"}));
                        continue;
                    }
                    Ok(Some(Some(_))) => {} // admin — allowed
                }
                let mut update_err: Option<Value> = None;
                let mut simple_ops: Vec<SimplePropPatch<'_>> = Vec::new();
                let mut member_ops: Vec<SpaceMemberOp<'_>> = Vec::new();
                // Phase 1 (validate + collect, no writes): parse every patch
                // path and value into typed ops before touching the store.
                // This ensures RFC 8620 §7.1 atomicity for input errors: a bad
                // role or wrong-type name rejects the whole patch with no writes.
                // `simple_ops` and `member_ops` are consumed by Phase 2.
                for (path, value) in patch_map.iter() {
                    match try_parse_simple_space_prop(path, value) {
                        Some(Ok(op)) => {
                            simple_ops.push(op);
                            continue;
                        }
                        Some(Err(e)) => {
                            update_err = Some(e);
                            break;
                        }
                        None => {} // not a simple prop; fall through to member-patch
                    }
                    // validate_member_patch guarantees "members/" prefix and
                    // non-empty contact_id, so the strip_prefix below is safe.
                    if let Err(e) = validate_member_patch(path, value) {
                        update_err = Some(e);
                        break;
                    }
                    let contact_id = path.strip_prefix("members/").unwrap();
                    let op = if value.is_null() {
                        SpaceMemberOp::Remove { contact_id }
                    } else {
                        // Phase 1 (validate_member_patch) already verified the role
                        // is a valid SpaceRole string if present; parse here is safe.
                        let role = value
                            .get("role")
                            .and_then(|v| v.as_str())
                            .and_then(SpaceRole::parse)
                            .unwrap_or(SpaceRole::Member);
                        SpaceMemberOp::Upsert { contact_id, role }
                    };
                    member_ops.push(op);
                }
                // Phase 2 (writes): all patches passed validation; apply atomically.
                // update_space_fully wraps prop updates and member ops in one
                // SQLite transaction — if any store write fails, the whole update
                // is rolled back, satisfying RFC 8620 §7.1 for server errors too.
                //
                // The match on SimplePropPatch is exhaustive: adding a new simple
                // prop requires a new variant, and the compiler flags missing arms.
                if update_err.is_none() {
                    let mut new_name: Option<&str> = None;
                    // None = description not in patch; Some(inner) = patch present,
                    // where inner=None clears the field and inner=Some(s) sets it.
                    let mut new_desc: Option<Option<&str>> = None;
                    for op in &simple_ops {
                        match op {
                            SimplePropPatch::Name(n) => new_name = Some(n),
                            SimplePropPatch::Description(d) => new_desc = Some(*d),
                        }
                    }
                    match store
                        .update_space_fully(space_id, new_name, new_desc, &member_ops)
                        .await
                    {
                        Ok(false) => {
                            update_err = Some(serde_json::json!({"type":"notFound"}));
                        }
                        Err(e) => {
                            tracing::error!("database error: {e}");
                            update_err = Some(serde_json::json!({
                                "type":"serverFail",
                                "description":"database error"
                            }));
                        }
                        Ok(true) => {}
                    }
                }
                if let Some(err) = update_err {
                    not_updated.insert(space_id.clone(), err);
                } else {
                    updated.insert(space_id.clone(), Value::Null);
                }
            } else {
                // RFC 8620 §7.1: a patch value that is not a JSON object is
                // invalid. Return notUpdated so the client knows the update
                // was rejected rather than silently dropped.
                not_updated.insert(
                    space_id.clone(),
                    serde_json::json!({
                        "type": "invalidArguments",
                        "description": "patch must be a JSON object"
                    }),
                );
            }
        }
    }

    // ── destroy ───────────────────────────────────────────────────────────
    if let Some(Value::Array(ids)) = args.get("destroy") {
        for id_val in ids {
            if let Some(id) = id_val.as_str() {
                // Single query: check existence and role atomically to avoid
                // a TOCTOU gap between separate space_exists / get_space_member_role
                // calls that could leak space existence via the forbidden path.
                match store.get_space_role_if_exists(id, &account_id).await {
                    Err(e) => {
                        not_destroyed.insert(id.to_string(), {
                            tracing::error!("database error: {e}");
                            serde_json::json!({"type":"serverFail","description":"database error"})
                        });
                        continue;
                    }
                    Ok(None) => {
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type": "notFound"}));
                        continue;
                    }
                    Ok(Some(None)) => {
                        // Space exists but caller is not a member.
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type": "forbidden"}));
                        continue;
                    }
                    Ok(Some(Some(role))) if role != crate::store::SpaceRole::Admin => {
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type": "forbidden"}));
                        continue;
                    }
                    Ok(Some(Some(_))) => {} // admin — allowed
                }
                match store.delete_space(id).await {
                    Ok(true) => destroyed.push(Value::String(id.to_string())),
                    Ok(false) => {
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type":"notFound"}));
                    }
                    Err(e) => {
                        not_destroyed.insert(id.to_string(), {
                            tracing::error!("database error: {e}");
                            serde_json::json!({"type":"serverFail","description":"database error"})
                        });
                    }
                }
            }
        }
    }

    let new_state = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    method_ok(
        "Space/set",
        serde_json::json!({
            "accountId": account_id,
            "oldState": old_state,
            "newState": new_state,
            "created": created,
            "notCreated": not_created,
            "updated": updated,
            "notUpdated": not_updated,
            "destroyed": destroyed,
            "notDestroyed": not_destroyed,
        }),
    )
}

async fn space_query(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let query_state = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    let ids = match store.query_spaces(&account_id).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    let total = ids.len() as i64;
    method_ok(
        "Space/query",
        serde_json::json!({
            "accountId": account_id,
            "queryState": query_state,
            "canCalculateChanges": false,
            "position": 0,
            "ids": ids,
            "total": total,
        }),
    )
}

async fn space_query_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let since = args
        .get("sinceQueryState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    if since != new_state {
        // The daemon has no per-object change log.  Space/query already
        // advertises canCalculateChanges:false; returning cannotCalculateChanges
        // here is the correct RFC 8620 §5.4 response when clients call anyway.
        // Returning all IDs as `added` would be wrong — the client would treat
        // every space as newly added on every poll after any mutation.
        return (
            "error".to_string(),
            serde_json::json!({"type": "cannotCalculateChanges", "newState": new_state}),
        );
    }
    // State unchanged — nothing added or removed.
    let ids = match store.query_spaces(&account_id).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };
    let total = ids.len() as i64;
    method_ok(
        "Space/queryChanges",
        serde_json::json!({
            "accountId": account_id,
            "oldQueryState": since,
            "newQueryState": new_state,
            "removed": [],
            "added": [],
            "total": total,
        }),
    )
}

/// Space/join — accept a space invite by its user-shareable code.
///
/// Arguments: `{ "accountId": "...", "code": "<invite-code>" }`.
/// Adds the caller as a member of the space and returns the space ID.
async fn space_join(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let code = match args.get("code").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => return method_error("invalidArguments"),
    };
    if code.len() > 128 {
        return method_error("invalidArguments");
    }
    use crate::store::SpaceJoinOutcome;
    match store.use_space_invite_code(&code, &account_id).await {
        Ok(SpaceJoinOutcome::Joined(space_id)) => {
            method_ok("Space/join", serde_json::json!({ "spaceId": space_id }))
        }
        Ok(SpaceJoinOutcome::AlreadyMember(_)) => (
            "error".to_string(),
            serde_json::json!({
                "type": "alreadyMember",
                "description": "already a member of this space"
            }),
        ),
        Ok(SpaceJoinOutcome::NotFound) => (
            "error".to_string(),
            serde_json::json!({
                "type": "notFound",
                "description": "invite code not found or expired"
            }),
        ),
        Err(e) => db_error(e),
    }
}

// ── SpaceInvite/* handlers (nie-7ew5) ─────────────────────────────────────────

fn space_invite_to_json(inv: &crate::store::SpaceInviteRow) -> Value {
    serde_json::json!({
        "id": inv.id,
        "code": inv.code,
        "spaceId": inv.space_id,
        "createdBy": inv.created_by,
        "createdAt": inv.created_at,
        "expiresAt": inv.expires_at,
    })
}

async fn space_invite_get(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let ids_opt: Option<Vec<String>> = match args.get("ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        ),
        _ => return method_error("invalidArguments"),
    };
    let id_strs: Option<Vec<&str>> = ids_opt
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());
    let state_tok = match store.state_token("SpaceInvite").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    match store
        .get_space_invites(id_strs.as_deref(), &account_id)
        .await
    {
        Ok((invites, not_found)) => method_ok(
            "SpaceInvite/get",
            serde_json::json!({
                "accountId": account_id,
                "state": state_tok,
                "list": invites.iter().map(space_invite_to_json).collect::<Vec<_>>(),
                "notFound": not_found,
            }),
        ),
        Err(e) => db_error(e),
    }
}

/// SpaceInvite/set — create new invites only.
///
/// Server assigns both `id` and `code`; clients MUST NOT supply either.
/// `update` always returns `forbidden` SetError per spec.
async fn space_invite_set(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let old_state = match store.state_token("SpaceInvite").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut not_destroyed = serde_json::Map::new();

    // ── create ────────────────────────────────────────────────────────────
    if let Some(Value::Object(creates)) = args.get("create") {
        for (client_id, props) in creates {
            // Reject client-supplied id or code fields
            if props.get("id").is_some() || props.get("code").is_some() {
                not_created.insert(
                    client_id.clone(),
                    serde_json::json!({"type":"invalidProperties","properties":["id","code"],"description":"server assigns id and code"}),
                );
                continue;
            }
            let space_id = match props.get("spaceId").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["spaceId"]}),
                    );
                    continue;
                }
            };
            // Require the caller to be a member of the space.  Without this
            // check, any authenticated user can create invite codes for spaces
            // they do not belong to, granting others unauthorized membership.
            match store.get_space_member_role(&space_id, &account_id).await {
                Ok(None) => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({
                            "type": "forbidden",
                            "description": "you must be a member of the space to create an invite"
                        }),
                    );
                    continue;
                }
                Err(e) => {
                    not_created.insert(client_id.clone(), {
                        tracing::error!("database error: {e}");
                        serde_json::json!({"type":"serverFail","description":"database error"})
                    });
                    continue;
                }
                Ok(Some(_)) => {} // caller is a member, proceed
            }
            let id = crate::store::Store::new_id();
            // Use chars [10..18] of the ULID — 8 Crockford Base32 chars from the
            // random suffix (~40-bit entropy).  [..8] would be pure timestamp:
            // zero random bits and trivially enumerable.
            let code = Ulid::new().to_string()[10..18].to_uppercase();
            match store
                .create_space_invite(&id, &code, &space_id, &account_id)
                .await
            {
                Ok(()) => {
                    created.insert(
                        client_id.clone(),
                        serde_json::json!({ "id": id, "code": code }),
                    );
                }
                Err(e) => {
                    not_created.insert(client_id.clone(), {
                        tracing::error!("database error: {e}");
                        serde_json::json!({"type":"serverFail","description":"database error"})
                    });
                }
            }
        }
    }

    // ── update: always forbidden ──────────────────────────────────────────
    if let Some(Value::Object(updates)) = args.get("update") {
        for (id, _) in updates {
            not_updated.insert(
                id.clone(),
                serde_json::json!({"type":"forbidden","description":"SpaceInvite objects are immutable"}),
            );
        }
    }

    // ── destroy ───────────────────────────────────────────────────────────
    // Members may revoke invites for spaces they belong to (RFC 8620 §5.3).
    // Non-members and non-existent IDs both get notFound (no membership leak).
    let mut destroyed: Vec<Value> = Vec::new();
    if let Some(Value::Array(ids)) = args.get("destroy") {
        for id_val in ids {
            let Some(id) = id_val.as_str() else { continue };
            match store.delete_space_invite(id, &account_id).await {
                Ok(true) => destroyed.push(Value::String(id.to_string())),
                Ok(false) => {
                    not_destroyed.insert(id.to_string(), serde_json::json!({"type":"notFound"}));
                }
                Err(e) => return db_error(e),
            }
        }
    }

    let new_state = match store.state_token("SpaceInvite").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    method_ok(
        "SpaceInvite/set",
        serde_json::json!({
            "accountId": account_id,
            "oldState": old_state,
            "newState": new_state,
            "created": created,
            "notCreated": not_created,
            "updated": {},
            "notUpdated": not_updated,
            "destroyed": destroyed,
            "notDestroyed": not_destroyed,
        }),
    )
}

// ── Message/* handlers (nie-ib2s) ─────────────────────────────────────────────

async fn message_get(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    // RFC 8620 §5.1: ids=null means "return all objects".
    let ids_opt: Option<Vec<String>> = match args.get("ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        ),
        _ => return method_error("invalidArguments"),
    };
    if let Some(ref ids) = ids_opt {
        if ids.len() > 4096 {
            return invalid_args("too many ids");
        }
    }
    let state_tok = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    const MAX_GET_ALL: i64 = 256;
    let (list, not_found) = if let Some(ref ids) = ids_opt {
        let id_strs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        match store.get_messages(&id_strs).await {
            Ok(r) => r,
            Err(e) => return db_error(e),
        }
    } else {
        // ids=null: return all messages (capped)
        let Some(channel_id) = state.default_channel_id() else {
            return server_fail("no default channel");
        };
        match store.query_messages(channel_id, 0, MAX_GET_ALL).await {
            Ok(ids) => {
                let id_strs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
                match store.get_messages(&id_strs).await {
                    Ok(r) => r,
                    Err(e) => return db_error(e),
                }
            }
            Err(e) => return db_error(e),
        }
    };
    method_ok(
        "Message/get",
        serde_json::json!({
            "accountId": account_id,
            "state": state_tok,
            "list": list.iter().map(message_to_json).collect::<Vec<_>>(),
            "notFound": not_found,
        }),
    )
}

async fn message_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    let since_state = args
        .get("sinceState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    // Simplified: if unchanged → empty; else return up to 256 message IDs as "created".
    const MAX_CHANGES: i64 = 256;
    let (created, has_more) = if since_state == new_state {
        (vec![], false)
    } else {
        // We don't have a cheap "all message ids" query — use default channel only.
        match state.default_channel_id() {
            Some(chan) => match store.query_messages(chan, 0, MAX_CHANGES).await {
                Ok(ids) => {
                    let total = store.count_messages_in_chat(chan).await.unwrap_or(0);
                    let has_more = total > MAX_CHANGES;
                    (ids, has_more)
                }
                Err(e) => return db_error(e),
            },
            None => (vec![], false),
        }
    };
    method_ok(
        "Message/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since_state,
            "newState": new_state,
            "hasMoreChanges": has_more,
            "removed": [],
            "created": created,
            "updated": [],
        }),
    )
}

async fn message_set(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };

    let old_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    let mut created: HashMap<String, Value> = HashMap::new();
    let mut not_created: HashMap<String, Value> = HashMap::new();
    let mut updated: HashMap<String, Value> = HashMap::new();
    let mut not_updated: HashMap<String, Value> = HashMap::new();
    let mut destroyed: Vec<Value> = Vec::new();
    let mut not_destroyed: HashMap<String, Value> = HashMap::new();

    if let Some(Value::Object(creates)) = args.get("create") {
        for (client_id, props) in creates {
            let chat_id = match props.get("chatId").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["chatId"]}),
                    );
                    continue;
                }
            };
            let body = match props.get("body").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["body"]}),
                    );
                    continue;
                }
            };
            if body.len() > 65536 {
                not_created.insert(
                    client_id.clone(),
                    serde_json::json!({"type":"invalidProperties","properties":["body"],"description":"body exceeds 65536 bytes"}),
                );
                continue;
            }

            // Optional fields
            let reply_to = props
                .get("replyTo")
                .and_then(|v| v.as_str())
                .map(String::from);
            if reply_to.as_deref().map(|s| s.len()).unwrap_or(0) > 128 {
                not_created.insert(
                    client_id.clone(),
                    serde_json::json!({"type":"invalidArguments","description":"replyTo exceeds 128 bytes"}),
                );
                continue;
            }
            let thread_root_id = props
                .get("threadRootId")
                .and_then(|v| v.as_str())
                .map(String::from);
            if thread_root_id.as_deref().map(|s| s.len()).unwrap_or(0) > 128 {
                not_created.insert(
                    client_id.clone(),
                    serde_json::json!({"type":"invalidArguments","description":"threadRootId exceeds 128 bytes"}),
                );
                continue;
            }
            // Normalize senderExpiresAt to SQLite datetime format so that the
            // expires_at <= datetime('now') comparison in hard_delete_expired_messages
            // works correctly.  RFC 3339 "T" separators compare incorrectly against
            // SQLite's space-separated datetime() output.
            let expires_at = match props.get("senderExpiresAt").and_then(|v| v.as_str()) {
                None => None,
                Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
                    Ok(dt) => Some(dt.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string()),
                    Err(_) => {
                        not_created.insert(
                            client_id.clone(),
                            serde_json::json!({
                                "type": "invalidProperties",
                                "properties": ["senderExpiresAt"],
                                "description": "senderExpiresAt must be a valid RFC 3339 datetime"
                            }),
                        );
                        continue;
                    }
                },
            };
            let burn_on_read = props
                .get("burnOnRead")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Verify the chat exists before inserting (RFC 8620 §5.3: a
            // reference to a nonexistent object must produce invalidProperties,
            // not serverFail).
            let chat_space_id = match store.get_chats(Some(&[chat_id.as_str()])).await {
                Err(e) => {
                    not_created.insert(client_id.clone(), db_error(e).1);
                    continue;
                }
                Ok((_, not_found)) if !not_found.is_empty() => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({
                            "type": "invalidProperties",
                            "description": "chatId does not exist",
                            "properties": ["chatId"]
                        }),
                    );
                    continue;
                }
                Ok((chats, _)) => chats.into_iter().next().and_then(|c| c.space_id),
            };

            // For space channels, verify the caller is a member of the space.
            if let Some(ref space_id) = chat_space_id {
                match store.get_space_member_role(space_id, &account_id).await {
                    Err(e) => {
                        not_created.insert(client_id.clone(), db_error(e).1);
                        continue;
                    }
                    Ok(None) => {
                        not_created.insert(
                            client_id.clone(),
                            serde_json::json!({
                                "type": "forbidden",
                                "description": "not a member of this space"
                            }),
                        );
                        continue;
                    }
                    Ok(Some(_)) => {}
                }
            }

            // Validate replyTo and threadRootId reference real messages in
            // this chat.  Storing arbitrary strings would let clients fake
            // thread structure pointing at non-existent messages.
            if let Some(ref reply_id) = reply_to {
                match store.message_exists_in_chat(reply_id, &chat_id).await {
                    Err(e) => {
                        not_created.insert(client_id.clone(), db_error(e).1);
                        continue;
                    }
                    Ok(false) => {
                        not_created.insert(
                            client_id.clone(),
                            serde_json::json!({
                                "type": "invalidArguments",
                                "description": "replyTo message not found in this chat"
                            }),
                        );
                        continue;
                    }
                    Ok(true) => {}
                }
            }
            if let Some(ref root_id) = thread_root_id {
                match store.message_exists_in_chat(root_id, &chat_id).await {
                    Err(e) => {
                        not_created.insert(client_id.clone(), db_error(e).1);
                        continue;
                    }
                    Ok(false) => {
                        not_created.insert(
                            client_id.clone(),
                            serde_json::json!({
                                "type": "invalidArguments",
                                "description": "threadRootId message not found in this chat"
                            }),
                        );
                        continue;
                    }
                    Ok(true) => {}
                }
            }

            // Store message locally.
            let now = chrono::Utc::now().to_rfc3339();
            let msg_id = match store
                .insert_message_ext(
                    &chat_id,
                    state.my_pub_id(),
                    &body,
                    &now,
                    reply_to.as_deref(),
                    thread_root_id.as_deref(),
                    expires_at.as_deref(),
                    burn_on_read,
                )
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    not_created.insert(client_id.clone(), db_error(e).1);
                    continue;
                }
            };

            // Encrypt and send via relay if MLS client available.
            if let Some(mls) = state.mls_client().await {
                let clear = ClearMessage::PeerDeliver {
                    message_id: msg_id.clone(),
                    chat_id: chat_id.clone(),
                    body: body.clone(),
                    body_type: "text/plain".to_string(),
                    sent_at: now.clone(),
                    reply_to: reply_to.clone(),
                    thread_root_id: thread_root_id.clone(),
                };
                let payload_bytes = serde_json::to_vec(&clear).unwrap();
                let encrypted = mls.lock().await.encrypt(&payload_bytes);
                match encrypted {
                    Ok(cipher) => match pad(&cipher) {
                        Ok(padded) => {
                            if let Some(tx) = state.relay_tx().await {
                                let rpc = JsonRpcRequest::new(
                                    next_request_id(),
                                    rpc_methods::BROADCAST,
                                    BroadcastParams { payload: padded },
                                )
                                .unwrap();
                                let _ = tx.send(rpc).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Message/set: MLS payload too large to pad: {e}");
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Message/set: MLS encrypt failed: {e}");
                        // Message stored locally — continue without relay send.
                    }
                }
            }

            created.insert(client_id.clone(), serde_json::json!({ "id": msg_id }));
        }
    }

    // ── update ──────────────────────────────────────────────────────────────
    if let Some(Value::Object(updates)) = args.get("update") {
        for (msg_id, patch) in updates {
            // Note: no outer existence/ownership pre-check here.  Each store
            // call in Phase 2 returns its own not-found or forbidden result.
            // edit_message_body has an internal ownership check (EditBodyResult::Forbidden).
            // A redundant outer check creates a TOCTOU window and was removed.
            if let Some(Value::Object(patch_map)) = Some(patch) {
                // Phase 1: validate all patch paths and value types before
                // writing anything to the DB.  This prevents partial-state
                // where an early field write succeeds but a later field fails
                // type validation, leaving the message in an inconsistent state.
                let mut validate_err: Option<Value> = None;
                for (path, value) in patch_map.iter() {
                    if let Some(reaction_id) = path.strip_prefix("reactions/") {
                        // reaction_id: max 64 chars, ASCII printable only (0x20–0x7E).
                        if reaction_id.len() > 64
                            || !reaction_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
                        {
                            validate_err = Some(serde_json::json!({
                                "type": "invalidArguments",
                                "description": "reaction_id must be 1–64 ASCII printable characters"
                            }));
                            break;
                        }
                        if !value.is_null() && !value.is_object() {
                            validate_err = Some(serde_json::json!({
                                "type": "invalidArguments",
                                "description": "reaction value must be null (to remove) or an object"
                            }));
                            break;
                        }
                        // When adding a reaction (value is an object), validate emoji length.
                        if value.is_object() {
                            if let Some(emoji_str) = value.get("emoji").and_then(|v| v.as_str()) {
                                if emoji_str.len() > 32 {
                                    validate_err = Some(serde_json::json!({
                                        "type": "invalidArguments",
                                        "description": "emoji must not exceed 32 bytes"
                                    }));
                                    break;
                                }
                            }
                        }
                    } else if path == "body" {
                        if value.as_str().is_none() {
                            validate_err = Some(serde_json::json!({
                                "type": "invalidArguments",
                                "description": "body must be a string"
                            }));
                            break;
                        }
                    } else if path == "deletedAt" {
                        if !value.is_string() {
                            validate_err = Some(serde_json::json!({
                                "type": "invalidArguments",
                                "description": "deletedAt must be a string timestamp"
                            }));
                            break;
                        }
                    } else if path == "readAt" {
                        match value.as_str() {
                            None => {
                                validate_err = Some(serde_json::json!({
                                    "type": "invalidArguments",
                                    "description": "readAt must be a string"
                                }));
                                break;
                            }
                            Some(s) => {
                                if chrono::DateTime::parse_from_rfc3339(s).is_err() {
                                    validate_err = Some(serde_json::json!({
                                        "type": "invalidArguments",
                                        "description": "readAt must be a valid RFC 3339 timestamp"
                                    }));
                                    break;
                                }
                            }
                        }
                    } else {
                        // nie-u966.11: JMAP spec requires unknown patch paths to
                        // return invalidArguments rather than being silently ignored.
                        validate_err = Some(serde_json::json!({
                            "type": "invalidArguments",
                            "description": format!("unknown patch path: {path}")
                        }));
                        break;
                    }
                }
                if let Some(err) = validate_err {
                    not_updated.insert(msg_id.clone(), err);
                    continue;
                }

                // Phase 2: all paths validated — apply writes.
                let mut update_err: Option<Value> = None;
                for (path, value) in patch_map {
                    if let Some(reaction_id) = path.strip_prefix("reactions/") {
                        if value.is_null() {
                            match store.remove_message_reaction(msg_id, reaction_id).await {
                                Ok(false) => {
                                    update_err = Some(serde_json::json!({"type":"notFound"}));
                                    break;
                                }
                                Err(e) => {
                                    tracing::error!("database error: {e}");
                                    update_err = Some(serde_json::json!({
                                        "type": "serverFail",
                                        "description": "database error"
                                    }));
                                    break;
                                }
                                Ok(true) => {}
                            }
                        } else {
                            // value.is_object() — validated above
                            let emoji = value.get("emoji").and_then(|v| v.as_str()).unwrap_or("?");
                            let sent_at = value
                                .get("sentAt")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            match store
                                .set_message_reaction(msg_id, reaction_id, emoji, sent_at)
                                .await
                            {
                                Ok(false) => {
                                    update_err = Some(serde_json::json!({"type":"notFound"}));
                                    break;
                                }
                                Err(e) => {
                                    tracing::error!("database error: {e}");
                                    update_err = Some(serde_json::json!({
                                        "type": "serverFail",
                                        "description": "database error"
                                    }));
                                    break;
                                }
                                Ok(true) => {}
                            }
                        }
                    } else if path == "body" {
                        // value.as_str() is Some — validated above
                        let new_body = value.as_str().unwrap();
                        // nie-f0pz.12: cap body at 65536 bytes.
                        if new_body.len() > 65536 {
                            update_err = Some(serde_json::json!({
                                "type": "invalidArguments",
                                "description": "body exceeds maximum length of 65536 bytes"
                            }));
                            break;
                        }
                        match store
                            .edit_message_body(msg_id, state.my_pub_id(), new_body)
                            .await
                        {
                            Ok(EditBodyResult::NotFound) => {
                                update_err = Some(serde_json::json!({"type":"notFound"}));
                                break;
                            }
                            // nie-f0pz.13: caller is not the sender → forbidden,
                            // not notFound, to avoid leaking message existence.
                            Ok(EditBodyResult::Forbidden) => {
                                update_err = Some(serde_json::json!({"type":"forbidden"}));
                                break;
                            }
                            Err(e) => {
                                update_err = Some({
                                    tracing::error!("database error: {e}");
                                    serde_json::json!({"type":"serverFail","description":"database error"})
                                });
                                break;
                            }
                            Ok(EditBodyResult::Updated) => {}
                        }
                    } else if path == "deletedAt" {
                        // value.is_string() — validated above.
                        // null is rejected: setting deletedAt to null would
                        // semantically mean "un-delete", which is not implemented.
                        match store.soft_delete_message(msg_id, false).await {
                            Ok(false) => {
                                update_err = Some(serde_json::json!({"type":"notFound"}));
                                break;
                            }
                            Err(e) => {
                                update_err = Some({
                                    tracing::error!("database error: {e}");
                                    serde_json::json!({"type":"serverFail","description":"database error"})
                                });
                                break;
                            }
                            Ok(true) => {}
                        }
                    } else if path == "readAt" {
                        // value.as_str() is Some — validated above
                        let ts = value.as_str().unwrap();
                        if let Err(e) = store.read_message(msg_id, ts).await {
                            update_err = Some({
                                tracing::error!("database error: {e}");
                                serde_json::json!({"type":"serverFail","description":"database error"})
                            });
                            break;
                        }
                    }
                    // All known paths handled above; unknown paths rejected in Phase 1.
                }
                if let Some(err) = update_err {
                    not_updated.insert(msg_id.clone(), err);
                } else {
                    updated.insert(msg_id.clone(), serde_json::json!(null));
                }
            } else {
                // Patch must be a JSON object — null, array, or scalar values
                // are rejected so the client gets deterministic feedback instead
                // of silent disappearance from both updated and notUpdated.
                not_updated.insert(
                    msg_id.clone(),
                    serde_json::json!({
                        "type": "invalidArguments",
                        "description": "patch must be a JSON object"
                    }),
                );
            }
        }
    }

    // ── destroy ─────────────────────────────────────────────────────────────
    if let Some(Value::Array(ids)) = args.get("destroy") {
        for id_val in ids {
            if let Some(id) = id_val.as_str() {
                // Fetch the message first to check existence and ownership.
                match store.get_messages(&[id]).await {
                    Err(e) => {
                        not_destroyed.insert(id.to_string(), {
                            tracing::error!("database error: {e}");
                            serde_json::json!({"type":"serverFail","description":"database error"})
                        });
                        continue;
                    }
                    Ok((rows, _)) => {
                        if rows.is_empty() {
                            not_destroyed
                                .insert(id.to_string(), serde_json::json!({"type":"notFound"}));
                            continue;
                        }
                        if rows[0].sender_id != account_id {
                            not_destroyed.insert(
                                id.to_string(),
                                serde_json::json!({"type":"forbidden","description":"not the message sender"}),
                            );
                            continue;
                        }
                    }
                }
                match store.hard_delete_message(id).await {
                    Ok(true) => destroyed.push(Value::String(id.to_string())),
                    Ok(false) => {
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type":"notFound"}));
                    }
                    Err(e) => {
                        not_destroyed.insert(id.to_string(), {
                            tracing::error!("database error: {e}");
                            serde_json::json!({"type":"serverFail","description":"database error"})
                        });
                    }
                }
            }
        }
    }

    let new_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    method_ok(
        "Message/set",
        serde_json::json!({
            "accountId": account_id,
            "oldState": old_state,
            "newState": new_state,
            "created": created,
            "updated": updated,
            "destroyed": destroyed,
            "notCreated": not_created,
            "notUpdated": not_updated,
            "notDestroyed": not_destroyed,
        }),
    )
}

async fn message_query(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };

    // chatId filter is REQUIRED — return unsupportedFilter if absent.
    let chat_id = match args
        .get("filter")
        .and_then(|f| f.get("chatId"))
        .and_then(|v| v.as_str())
    {
        Some(id) => id.to_string(),
        None => {
            return (
                "error".to_string(),
                serde_json::json!({
                    "type": "unsupportedFilter",
                    "description": "chatId filter is required"
                }),
            )
        }
    };

    let query_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };

    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(256);
    if position < 0 {
        return invalid_args("position must be non-negative");
    }
    if limit < 0 {
        return invalid_args("limit must be non-negative");
    }
    let total = match store.count_messages_in_chat(&chat_id).await {
        Ok(n) => n,
        Err(e) => return db_error(e),
    };
    let ids = match store.query_messages(&chat_id, position, limit).await {
        Ok(v) => v,
        Err(e) => return db_error(e),
    };

    method_ok(
        "Message/query",
        serde_json::json!({
            "accountId": account_id,
            "queryState": query_state,
            "canCalculateChanges": false,
            "position": position,
            "ids": ids,
            "total": total,
        }),
    )
}

async fn message_query_changes(args: Value, state: &DaemonState) -> (String, Value) {
    let account_id = match validate_account_id(&args, state) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(store) = state.store() else {
        return server_fail("store not initialized");
    };
    // chatId filter is REQUIRED
    let chat_id = match args
        .get("filter")
        .and_then(|f| f.get("chatId"))
        .and_then(|v| v.as_str())
    {
        Some(id) => id.to_string(),
        None => {
            return (
                "error".to_string(),
                serde_json::json!({"type":"unsupportedFilter","description":"chatId filter is required"}),
            )
        }
    };
    let since = args
        .get("sinceQueryState")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let new_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return db_error(e),
    };
    let total = match store.count_messages_in_chat(&chat_id).await {
        Ok(n) => n,
        Err(e) => return db_error(e),
    };
    const MAX_QUERY_CHANGES: i64 = 256;
    let added: Vec<Value> = if since == new_state {
        vec![]
    } else {
        let ids = match store.query_messages(&chat_id, 0, MAX_QUERY_CHANGES).await {
            Ok(v) => v,
            Err(e) => return db_error(e),
        };
        ids.iter()
            .enumerate()
            .map(|(i, id)| serde_json::json!({"index": i, "id": id}))
            .collect()
    };
    method_ok(
        "Message/queryChanges",
        serde_json::json!({
            "accountId": account_id,
            "oldQueryState": since,
            "newQueryState": new_state,
            "removed": [],
            "added": added,
            "total": total,
        }),
    )
}

// ── Blob upload/download (RFC 8620 §6) ────────────────────────────────────────

/// POST /jmap/upload/:account_id
///
/// Upload raw bytes.  Returns a BlobDescriptor JSON object with the blobId.
/// The blobId is the hex-encoded SHA-256 of the content (content-addressed).
/// Maximum permitted upload size (RFC 8620 §6 maxSizeUpload).
const UPLOAD_MAX_BYTES: usize = 25 * 1024 * 1024; // 25 MB

pub async fn handle_jmap_upload(
    State(state): State<DaemonState>,
    Path(account_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if account_id != state.my_pub_id() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if body.len() > UPLOAD_MAX_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "upload exceeds limit").into_response();
    }
    let content_type_raw = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    if content_type_raw.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            "Content-Type header exceeds maximum length",
        )
            .into_response();
    }
    let content_type = content_type_raw.to_string();

    let blob_id = format!("{:x}", Sha256::digest(&body));
    let size = body.len();

    let Some(store) = state.store() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(e) = store.upsert_blob(&blob_id, &content_type, &body).await {
        tracing::warn!("blob upload: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "accountId": account_id,
            "blobId": blob_id,
            "type": content_type,
            "size": size,
        })),
    )
        .into_response()
}

/// Return a safe Content-Type for a stored blob.
///
/// Allows `image/*`, `audio/*`, `video/*`, and `application/octet-stream`
/// through unchanged.  Everything else — including `text/html` and
/// `text/javascript` — is coerced to `application/octet-stream` to prevent
/// the browser from rendering or executing the blob as active content.
fn sanitize_blob_content_type(stored: &str) -> String {
    let mime = stored
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let safe = mime.starts_with("image/")
        || mime.starts_with("audio/")
        || mime.starts_with("video/")
        || mime == "application/octet-stream";
    if safe {
        stored.to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

/// GET /jmap/download/:account_id/:blob_id/:name
///
/// Download a blob.  The `:name` segment is ignored (used by clients as the
/// download file name suggestion).
pub async fn handle_jmap_download(
    State(state): State<DaemonState>,
    Path((account_id, blob_id, _name)): Path<(String, String, String)>,
) -> axum::response::Response {
    if account_id != state.my_pub_id() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(store) = state.store() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match store.get_blob(&blob_id).await {
        Ok(Some((content_type, data))) => {
            let safe_ct = sanitize_blob_content_type(&content_type);
            (
                [
                    (header::CONTENT_TYPE, safe_ct),
                    (header::CONTENT_DISPOSITION, "attachment".to_string()),
                ],
                data,
            )
                .into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::warn!("blob download: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── EventSource push (RFC 8620 §7.3) ──────────────────────────────────────────

/// Query parameters for GET /jmap/eventsource/
#[derive(Deserialize)]
pub struct EventSourceParams {
    pub types: Option<String>,
    pub closeafter: Option<String>,
    pub ping: Option<u64>,
    /// Browser EventSource API cannot set headers; accept token in query string.
    pub token: Option<String>,
}

/// Carries all state across `stream::unfold` iterations for the SSE stream.
struct SseState {
    rx: tokio::sync::broadcast::Receiver<DaemonEvent>,
    daemon_state: DaemonState,
    /// `None` = emit events for all supported types.
    types_filter: Option<Vec<String>>,
    closeafter_state: bool,
    done: bool,
}

/// Map a `DaemonEvent` to an SSE event per RFC 8620 §7.3.
///
/// Most events produce a `state` event with updated state tokens.
/// `DaemonEvent::Typing` produces an ephemeral `typing` event instead.
/// Returns `None` if the event is not relevant or filtered out.
async fn daemon_event_to_jmap_event(
    event: &DaemonEvent,
    daemon_state: &DaemonState,
    types_filter: &Option<Vec<String>>,
) -> Option<sse::Event> {
    // Typing indicators are ephemeral: emit a custom `typing` event rather
    // than a `state` token update.
    if let DaemonEvent::Typing {
        from,
        chat_id,
        typing,
        ..
    } = event
    {
        if let Some(filter) = types_filter {
            if !filter.iter().any(|f| f == "Chat" || f == "*") {
                return None;
            }
        }
        let data = serde_json::json!({
            "senderId": from,
            "chatId": chat_id,
            "typing": typing,
        })
        .to_string();
        return Some(sse::Event::default().event("typing").data(data));
    }

    let changed_type: &str = match event {
        DaemonEvent::MessageReceived { .. } | DaemonEvent::MessageRetracted { .. } => "Message",
        DaemonEvent::UserJoined { .. }
        | DaemonEvent::UserLeft { .. }
        | DaemonEvent::DirectoryUpdated { .. } => "ChatContact",
        _ => return None,
    };

    if let Some(filter) = types_filter {
        if !filter.iter().any(|f| f == changed_type || f == "*") {
            return None;
        }
    }

    let store = daemon_state.store()?;
    let state_tok = store.state_token(changed_type).await.ok()?;
    let account_id = daemon_state.my_pub_id();

    let data = serde_json::json!({
        "changed": {
            account_id: { changed_type: state_tok }
        }
    })
    .to_string();

    Some(sse::Event::default().event("state").data(data))
}

/// GET /jmap/eventsource/ — RFC 8620 §7.3 Server-Sent Events push channel.
///
/// Auth: `Authorization: Bearer <token>` header or `?token=<token>` query param.
/// Params: `types` (comma-separated data types or `*`), `closeafter` (`state`|`no`),
///         `ping` (keep-alive interval in seconds, 0 = disabled).
pub async fn handle_jmap_eventsource(
    State(state): State<DaemonState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<EventSourceParams>,
) -> axum::response::Response {
    let auth_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| validate_token_header(h, state.token()))
        .unwrap_or(false)
        || params
            .token
            .as_deref()
            .map(|t| bool::from(t.as_bytes().ct_eq(state.token().as_bytes())))
            .unwrap_or(false);

    if !auth_ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // `None` types_filter means "all types"; otherwise filter by the listed names.
    let types_filter: Option<Vec<String>> = params.types.and_then(|t| {
        if t == "*" {
            None
        } else {
            Some(t.split(',').map(|s| s.trim().to_string()).collect())
        }
    });

    let closeafter_state = params.closeafter.as_deref() == Some("state");
    let ping_secs = params.ping.unwrap_or(0);

    let sse_state = SseState {
        rx: state.subscribe_events(),
        daemon_state: state,
        types_filter,
        closeafter_state,
        done: false,
    };

    let stream = futures::stream::unfold(sse_state, |mut s| async move {
        if s.done {
            return None;
        }
        loop {
            match s.rx.recv().await {
                Ok(event) => {
                    if let Some(sse_event) =
                        daemon_event_to_jmap_event(&event, &s.daemon_state, &s.types_filter).await
                    {
                        s.done = s.closeafter_state;
                        return Some((Ok::<_, std::convert::Infallible>(sse_event), s));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    let sse_response = sse::Sse::new(stream);
    if ping_secs > 0 {
        sse_response
            .keep_alive(sse::KeepAlive::new().interval(std::time::Duration::from_secs(ping_secs)))
            .into_response()
    } else {
        sse_response.into_response()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DaemonState;

    fn make_state() -> DaemonState {
        DaemonState::new(
            "a".repeat(64),
            "test-token".to_string(),
            Some("Alice".to_string()),
            "mainnet".to_string(),
            None,
            None,
        )
    }

    #[tokio::test]
    async fn test_session_type_tag() {
        let state = make_state();
        let Json(session) = handle_jmap_session(State(state)).await.unwrap();
        assert_eq!(session.type_tag, "Session");
    }

    #[tokio::test]
    async fn test_session_has_chat_capability() {
        let state = make_state();
        let Json(session) = handle_jmap_session(State(state)).await.unwrap();
        assert!(
            session.capabilities.contains_key(CAP_CHAT),
            "session must advertise chat capability"
        );
        // Per spec the session-level value is {}
        assert_eq!(
            session.capabilities[CAP_CHAT],
            serde_json::json!({}),
            "chat capability value must be empty object"
        );
    }

    #[tokio::test]
    async fn test_session_account_has_supported_body_types() {
        let state = make_state();
        let Json(session) = handle_jmap_session(State(state)).await.unwrap();
        let acct = session
            .accounts
            .values()
            .next()
            .expect("must have one account");
        let chat_cap = acct
            .account_capabilities
            .get(CAP_CHAT)
            .expect("account must have chat capability");
        let body_types = chat_cap["supportedBodyTypes"]
            .as_array()
            .expect("supportedBodyTypes must be array");
        assert!(
            body_types.contains(&serde_json::json!("text/plain")),
            "text/plain must be supported"
        );
    }

    #[tokio::test]
    async fn test_session_primary_account_matches_pub_id() {
        let pub_id = "a".repeat(64);
        let state = DaemonState::new(
            pub_id.clone(),
            "tok".to_string(),
            None,
            "mainnet".to_string(),
            None,
            None,
        );
        let Json(session) = handle_jmap_session(State(state)).await.unwrap();
        assert_eq!(session.username, pub_id);
        assert_eq!(session.primary_accounts[CAP_CHAT], pub_id.as_str());
    }

    #[tokio::test]
    async fn test_session_url_fields() {
        let state = make_state();
        let Json(session) = handle_jmap_session(State(state)).await.unwrap();
        assert!(
            session.api_url.ends_with("/jmap"),
            "apiUrl must end with /jmap: {}",
            session.api_url
        );
        assert!(
            session.upload_url.contains("{accountId}"),
            "uploadUrl must contain {{accountId}}: {}",
            session.upload_url
        );
        assert!(
            session.download_url.contains("{blobId}"),
            "downloadUrl must contain {{blobId}}: {}",
            session.download_url
        );
        assert!(
            session.event_source_url.contains("{types}"),
            "eventSourceUrl must contain {{types}}: {}",
            session.event_source_url
        );
        assert!(
            session.event_source_url.contains("{closeafter}"),
            "eventSourceUrl must contain {{closeafter}}: {}",
            session.event_source_url
        );
        assert!(
            session.event_source_url.contains("{ping}"),
            "eventSourceUrl must contain {{ping}}: {}",
            session.event_source_url
        );
    }

    #[tokio::test]
    async fn test_jmap_request_unknown_method_returns_error() {
        let state = make_state();
        let req = JmapRequest {
            using: vec![CAP_CORE.to_string(), CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Foo/unknownVerb".to_string(),
                serde_json::json!({}),
                "c0".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state), Json(req)).await.unwrap();
        assert_eq!(resp.method_responses.len(), 1);
        let MethodResponse(method, result, call_id) = &resp.method_responses[0];
        assert_eq!(method, "error");
        assert_eq!(result["type"], "unknownMethod");
        assert_eq!(call_id, "c0");
    }

    #[tokio::test]
    async fn test_jmap_request_session_state_present() {
        let state = make_state();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![],
        };
        let Json(resp) = handle_jmap_request(State(state), Json(req)).await.unwrap();
        assert!(
            !resp.session_state.is_empty(),
            "sessionState must be non-empty"
        );
    }

    #[tokio::test]
    async fn test_jmap_request_empty_batch() {
        let state = make_state();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![],
        };
        let Json(resp) = handle_jmap_request(State(state), Json(req)).await.unwrap();
        assert!(resp.method_responses.is_empty());
    }

    #[tokio::test]
    async fn test_jmap_request_call_id_preserved() {
        let state = make_state();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![
                MethodCall("Foo/get".to_string(), Value::Null, "first".to_string()),
                MethodCall("Bar/set".to_string(), Value::Null, "second".to_string()),
            ],
        };
        let Json(resp) = handle_jmap_request(State(state), Json(req)).await.unwrap();
        assert_eq!(resp.method_responses[0].2, "first");
        assert_eq!(resp.method_responses[1].2, "second");
    }

    #[test]
    fn test_session_serializes_type_tag() {
        // Verify @type field serializes correctly — serde rename check.
        let state = DaemonState::new(
            "a".repeat(64),
            "t".to_string(),
            None,
            "mainnet".to_string(),
            None,
            None,
        );
        // Build a session synchronously using tokio block_on.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let session = rt.block_on(build_session(&state)).unwrap();
        let json = serde_json::to_value(&session).unwrap();
        assert_eq!(json["@type"], "Session");
    }

    // ── daemon_event_to_jmap_event: Typing ────────────────────────────────

    /// Typing events produce an SSE event (not None).
    /// The Typing branch in daemon_event_to_jmap_event must return Some.
    #[tokio::test]
    async fn test_typing_event_produces_sse_event() {
        let state = make_state();
        let event = DaemonEvent::Typing {
            from: "d".repeat(64),
            chat_id: "chan-01".to_string(),
            typing: true,
            timestamp: "2026-04-23T10:00:00Z".to_string(),
        };
        let sse = daemon_event_to_jmap_event(&event, &state, &None).await;
        assert!(sse.is_some(), "Typing event must produce an SSE event");
    }

    /// Typing events are filtered out when the types filter doesn't include Chat.
    #[tokio::test]
    async fn test_typing_event_filtered_by_types() {
        let state = make_state();
        let event = DaemonEvent::Typing {
            from: "d".repeat(64),
            chat_id: "chan-01".to_string(),
            typing: false,
            timestamp: "2026-04-23T10:00:00Z".to_string(),
        };
        let filter = Some(vec!["Message".to_string()]);
        let sse = daemon_event_to_jmap_event(&event, &state, &filter).await;
        assert!(sse.is_none(), "Typing must be filtered when types=Message");
    }

    // ── Space model tests (nie-7ew5) ──────────────────────────────────────

    /// Space/set create + Space/get roundtrip.
    #[tokio::test]
    async fn test_space_set_create_and_get() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);

        // Create a space
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": {
                        "s1": { "name": "Test Space", "description": "A test space" }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Space/set");
        let space_id = result["created"]["s1"]["id"]
            .as_str()
            .expect("created space must have id")
            .to_string();

        // Fetch it back via Space/get
        let req2 = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "ids": [space_id.clone()]
                }),
                "c2".to_string(),
            )],
        };
        let Json(resp2) = handle_jmap_request(State(state.clone()), Json(req2))
            .await
            .unwrap();
        let MethodResponse(method2, result2, _) = &resp2.method_responses[0];
        assert_eq!(method2, "Space/get");
        let list = result2["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], space_id.as_str());
        assert_eq!(list[0]["name"], "Test Space");
        // Creator must be in memberList with role=admin
        let members = list[0]["memberList"].as_array().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0]["contactId"], pub_id.as_str());
        assert_eq!(members[0]["role"], "admin");
    }

    /// Space/set create: missing name returns notCreated.
    #[tokio::test]
    async fn test_space_set_create_missing_name() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": { "s1": {} }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notCreated"]["s1"]["type"].as_str() == Some("invalidProperties"),
            "missing name must return invalidProperties: {result}"
        );
    }

    /// Space/set create with a non-string description must return notCreated
    /// with invalidProperties, not silently create the space with no description.
    #[tokio::test]
    async fn test_space_set_create_wrong_type_description_rejected() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": { "s1": { "name": "Valid Name", "description": 42 } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notCreated"]["s1"].is_object(),
            "wrong-type description must be in notCreated: {result}"
        );
        assert_eq!(
            result["notCreated"]["s1"]["type"], "invalidProperties",
            "error type must be invalidProperties"
        );
        assert!(
            result["created"].as_object().unwrap().is_empty(),
            "created must be empty when description type is invalid"
        );
    }

    /// SpaceInvite/set create + Space/join roundtrip.
    #[tokio::test]
    async fn test_space_invite_create_and_join() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);

        // Create a space first
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": { "s1": { "name": "Invite Space" } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let space_id = resp.method_responses[0].1["created"]["s1"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Create an invite
        let req2 = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "SpaceInvite/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": { "i1": { "spaceId": space_id } }
                }),
                "c2".to_string(),
            )],
        };
        let Json(resp2) = handle_jmap_request(State(state.clone()), Json(req2))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp2.method_responses[0];
        assert_eq!(method, "SpaceInvite/set");
        let code = result["created"]["i1"]["code"]
            .as_str()
            .expect("invite must have code")
            .to_string();
        let invite_id = result["created"]["i1"]["id"]
            .as_str()
            .expect("invite must have id")
            .to_string();

        // Verify code != id (distinct fields per spec)
        assert_ne!(code, invite_id, "code and id must be distinct");

        // Use the invite via Space/join
        let joiner = "b".repeat(64);
        let state2 = DaemonState::new(
            joiner.clone(),
            "token2".to_string(),
            None,
            "mainnet".to_string(),
            None,
            state.store().map(|s| s.clone()),
        );
        let req3 = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/join".to_string(),
                serde_json::json!({ "accountId": joiner, "code": code }),
                "c3".to_string(),
            )],
        };
        let Json(resp3) = handle_jmap_request(State(state2), Json(req3))
            .await
            .unwrap();
        let MethodResponse(method3, result3, _) = &resp3.method_responses[0];
        assert_eq!(method3, "Space/join", "join must succeed: {result3}");
        assert_eq!(result3["spaceId"], space_id.as_str());
    }

    /// SpaceInvite/set update must return forbidden.
    #[tokio::test]
    async fn test_space_invite_update_is_forbidden() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "SpaceInvite/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { "fake-id": { "expiresAt": "2099-01-01T00:00:00Z" } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert_eq!(
            result["notUpdated"]["fake-id"]["type"], "forbidden",
            "update must be forbidden: {result}"
        );
    }

    #[tokio::test]
    async fn test_space_invite_non_member_cannot_create() {
        // A user who is not a member of the space must not be able to create
        // an invite for it.  Before this fix, the invite was created silently,
        // allowing the non-member to grant arbitrary users access to the space.
        let state = make_store_state().await;
        let owner = "a".repeat(64);
        let outsider = "b".repeat(64);

        // Create a space as the owner
        let space_id = create_test_space(&state, "Private Space").await;

        // The outsider tries to create an invite for the same space
        let outsider_state = DaemonState::new(
            outsider.clone(),
            "token-outsider".to_string(),
            None,
            "mainnet".to_string(),
            None,
            state.store().map(|s| s.clone()),
        );
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "SpaceInvite/set".to_string(),
                serde_json::json!({
                    "accountId": outsider,
                    "create": { "i1": { "spaceId": space_id } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(outsider_state), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notCreated"]["i1"]["type"] == "forbidden",
            "non-member must not be able to create invite: {result}"
        );
        assert!(
            result["created"].as_object().unwrap().is_empty(),
            "created map must be empty when invite is rejected"
        );
        // Ensure the owner's space is unaffected
        let _ = owner; // silence unused warning
    }

    /// Space/query returns space IDs.
    #[tokio::test]
    async fn test_space_query() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);

        // The bootstrapped space from make_store_state
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/query".to_string(),
                serde_json::json!({ "accountId": pub_id }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Space/query");
        assert!(
            result["ids"].as_array().is_some(),
            "ids must be array: {result}"
        );
        // At least the bootstrapped space is present.
        assert!(
            result["total"].as_i64().unwrap_or(0) >= 1,
            "total must be >= 1"
        );
    }

    // ── message_set tests (require in-memory store) ────────────────────────

    async fn make_store_state() -> DaemonState {
        let store = crate::store::Store::new("sqlite::memory:")
            .await
            .expect("in-memory store");
        let space_id = "01SPACE0000000000000000000";
        let channel_id = "01CHAN00000000000000000000";
        let owner_pub_id = "a".repeat(64);
        store
            .create_space_full(space_id, "test", None, &owner_pub_id)
            .await
            .unwrap();
        store
            .create_channel(channel_id, "general", space_id)
            .await
            .unwrap();
        let state = DaemonState::new(
            "a".repeat(64),
            "token".to_string(),
            None,
            "mainnet".to_string(),
            None,
            Some(store),
        );
        state.set_default_space_id(space_id.to_string());
        state.set_default_channel_id(channel_id.to_string());
        state
    }

    #[tokio::test]
    async fn test_message_set_create_stores_message() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "create": {
                        "m1": { "chatId": channel_id, "body": "hello" }
                    }
                }),
                "c0".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Message/set");
        assert!(result["created"]["m1"]["id"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_message_set_destroy_removes_message() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "bye", "2026-04-23T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "destroy": [msg_id.clone()]
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Message/set");
        let destroyed = result["destroyed"].as_array().unwrap();
        assert_eq!(destroyed.len(), 1);
        assert_eq!(destroyed[0].as_str().unwrap(), msg_id);
        // Verify row gone from store
        let (found, not_found) = store.get_messages(&[&msg_id]).await.unwrap();
        assert!(found.is_empty());
        assert_eq!(not_found, vec![msg_id]);
    }

    #[tokio::test]
    async fn test_message_set_update_reaction() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "hi", "2026-04-23T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": {
                        msg_id.clone(): {
                            "reactions/01REACTION": { "emoji": "👍", "sentAt": "2026-04-23T01:00:00Z" }
                        }
                    }
                }),
                "c2".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Message/set");
        assert!(
            result["updated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "updated entry must appear in updated map"
        );

        // Verify reaction stored
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        let reactions: serde_json::Value = serde_json::from_str(&msgs[0].reactions).unwrap();
        assert_eq!(reactions["01REACTION"]["emoji"], "👍");
    }

    #[tokio::test]
    async fn test_message_set_update_soft_delete() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "text", "2026-04-23T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": {
                        msg_id.clone(): { "deletedAt": "2026-04-23T12:00:00Z" }
                    }
                }),
                "c3".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Message/set");
        assert!(result["notUpdated"].as_object().unwrap().is_empty());

        // Verify deleted_at is set
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        assert!(
            msgs[0].deleted_at.is_some(),
            "deleted_at must be set after soft delete"
        );
    }

    #[tokio::test]
    async fn test_message_set_create_with_expiry() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "create": {
                        "m1": {
                            "chatId": channel_id,
                            "body": "self-destruct",
                            // Set expiry in the past so the reaper would delete it
                            "senderExpiresAt": "2026-01-01T00:00:00Z",
                            "burnOnRead": false
                        }
                    }
                }),
                "c4".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        let msg_id = result["created"]["m1"]["id"].as_str().unwrap().to_string();

        // Verify expires_at was stored
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        // Stored in SQLite datetime format (normalized from RFC 3339 on write).
        assert_eq!(msgs[0].expires_at.as_deref(), Some("2026-01-01 00:00:00"));

        // Run the reaper — should hard-delete this message (past expiry)
        let deleted = store.hard_delete_expired_messages().await.unwrap();
        assert_eq!(deleted, 1);
        let (found, _) = store.get_messages(&[&msg_id]).await.unwrap();
        assert!(
            found.is_empty(),
            "expired message must be hard-deleted by reaper"
        );
    }

    // Regression: name/description patch paths must be handled as simple props
    // and not treated as unknown member-patch paths.  Before try_parse_simple_space_prop
    // was introduced, they fell through to member-patch validation and returned
    // invalidPatch.
    #[tokio::test]
    async fn test_space_set_update_name_succeeds() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Original Name").await;

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): { "name": "Updated Name" }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Space/set");
        assert!(
            result["notUpdated"].as_object().unwrap().is_empty(),
            "name update must succeed, got notUpdated: {}",
            result["notUpdated"]
        );
        // Use contains_key, not is_null(): serde_json returns &Value::Null for
        // missing keys, so is_null() would silently pass if the server dropped
        // the id from both updated and notUpdated.
        assert!(
            result["updated"]
                .as_object()
                .unwrap()
                .contains_key(&space_id),
            "updated space must appear in updated map"
        );

        // Verify the name was actually persisted.
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c2".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        assert_eq!(
            get_resp.method_responses[0].1["list"][0]["name"], "Updated Name",
            "name must be persisted after update"
        );
    }

    // ── Space/set member patch tests ──────────────────────────────────────────
    //
    // Oracle: RFC 8620 §5.3 (patch semantics) and VALID_ROLES.  These tests
    // exercise member patch handling through the Space/set update path, which
    // is the only entry point, so the full request stack is the correct locus.

    /// Helper: create a space via Space/set and return its server-assigned id.
    async fn create_test_space(state: &DaemonState, name: &str) -> String {
        let pub_id = "a".repeat(64);
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": { "s1": { "name": name } }
                }),
                "c0".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        resp.method_responses[0].1["created"]["s1"]["id"]
            .as_str()
            .expect("created space must have id")
            .to_string()
    }

    #[tokio::test]
    async fn test_space_member_patch_invalid_role_yields_invalid_arguments() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Role Test Space").await;
        let contact_id = "b".repeat(64);

        // Patch with an unrecognised role value.
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            format!("members/{contact_id}"): { "role": "superadmin" }
                        }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Space/set");
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "invalid role must appear in notUpdated, got: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidArguments",
            "invalid role must yield invalidArguments, got: {}",
            result["notUpdated"][&space_id]
        );
        // Space must not appear in updated.
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "invalid role must not appear in updated"
        );
    }

    #[tokio::test]
    async fn test_space_member_patch_unknown_path_yields_invalid_patch() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Path Test Space").await;

        // Patch with a path that does not start with "members/".
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            "settings/theme": "dark"
                        }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Space/set");
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "unknown patch path must appear in notUpdated, got: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidPatch",
            "unknown patch path must yield invalidPatch, got: {}",
            result["notUpdated"][&space_id]
        );
    }

    #[tokio::test]
    async fn test_space_member_patch_add_and_remove_roundtrip() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let contact_id = "b".repeat(64);
        let space_id = create_test_space(&state, "Member Roundtrip Space").await;

        // Add contact_id as moderator.
        let add_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            format!("members/{contact_id}"): { "role": "moderator" }
                        }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(add_resp) = handle_jmap_request(State(state.clone()), Json(add_req))
            .await
            .unwrap();
        let MethodResponse(_, add_result, _) = &add_resp.method_responses[0];
        assert!(
            add_result["notUpdated"].as_object().unwrap().is_empty(),
            "add member must succeed, got notUpdated: {}",
            add_result["notUpdated"]
        );
        assert!(
            add_result["updated"]
                .as_object()
                .unwrap()
                .contains_key(space_id.as_str()),
            "add member must appear in updated map"
        );

        // Verify member present with correct role via Space/get.
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c2".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        let members = get_resp.method_responses[0].1["list"][0]["memberList"]
            .as_array()
            .expect("memberList must be array");
        let added = members
            .iter()
            .find(|m| m["contactId"] == contact_id.as_str());
        assert!(added.is_some(), "added member must appear in memberList");
        assert_eq!(
            added.unwrap()["role"],
            "moderator",
            "member role must be moderator"
        );

        // Remove contact_id via null value.
        let remove_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            format!("members/{contact_id}"): serde_json::Value::Null
                        }
                    }
                }),
                "c3".to_string(),
            )],
        };
        let Json(remove_resp) = handle_jmap_request(State(state.clone()), Json(remove_req))
            .await
            .unwrap();
        let MethodResponse(_, remove_result, _) = &remove_resp.method_responses[0];
        assert!(
            remove_result["notUpdated"].as_object().unwrap().is_empty(),
            "remove member must succeed, got notUpdated: {}",
            remove_result["notUpdated"]
        );

        // Verify member is gone.
        let Json(get_resp2) = handle_jmap_request(
            State(state.clone()),
            Json(JmapRequest {
                using: vec![CAP_CHAT.to_string()],
                method_calls: vec![MethodCall(
                    "Space/get".to_string(),
                    serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                    "c4".to_string(),
                )],
            }),
        )
        .await
        .unwrap();
        let members2 = get_resp2.method_responses[0].1["list"][0]["memberList"]
            .as_array()
            .expect("memberList must be array");
        assert!(
            members2
                .iter()
                .all(|m| m["contactId"] != contact_id.as_str()),
            "removed member must not appear in memberList"
        );
    }

    // Regression: combined patch {name + members/* with invalid role} must be
    // fully rejected — name must NOT be written even though it is individually
    // valid.  Before Phase 1 validation was added, the name write went through
    // before the role was checked, producing notUpdated while the name change
    // had already been persisted (RFC 8620 §7.1 atomicity violation).
    #[tokio::test]
    async fn test_space_set_mixed_patch_invalid_role_leaves_name_unchanged() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let contact_id = "b".repeat(64);
        let space_id = create_test_space(&state, "Original Name").await;

        // Combined patch: valid name + invalid role.
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            "name": "Should Not Apply",
                            format!("members/{contact_id}"): { "role": "superadmin" }
                        }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "combined patch with invalid role must be in notUpdated, got: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidArguments",
            "error must be invalidArguments"
        );
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "updated must be empty when patch fails"
        );

        // Atomicity check: name must not have been written.
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c2".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        assert_eq!(
            get_resp.method_responses[0].1["list"][0]["name"], "Original Name",
            "name must not be written when notUpdated is returned"
        );
    }

    // Non-string role values (e.g. {"role": 42}) must be rejected with
    // invalidArguments rather than silently coercing to "member".
    #[tokio::test]
    async fn test_space_set_non_string_role_rejected() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let contact_id = "b".repeat(64);
        let space_id = create_test_space(&state, "Name").await;

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            format!("members/{contact_id}"): { "role": 42 }
                        }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "non-string role must be in notUpdated, got: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidArguments",
            "error type must be invalidArguments for non-string role"
        );
    }

    // Regression: "members/" (trailing slash, empty contact id) must be rejected
    // as invalidPatch.  Before the fix, strip_prefix returned Some("") and the
    // empty string was discarded via `let Some(_) = ...`, so the path passed
    // validation and an empty-id row reached the store.
    //
    // Also verifies atomicity: a combined {"name":"New","members/":...} patch
    // must not write the name when the empty-id path is rejected in Phase 1.
    #[tokio::test]
    async fn test_space_set_empty_contact_id_rejected() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Stable Name").await;

        // Standalone "members/" patch must be invalidPatch.
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            "members/": { "role": "member" }
                        }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "empty contact_id must be in notUpdated, got: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidPatch",
            "error type must be invalidPatch"
        );

        // Combined patch: valid name + empty-id member path.
        // Phase 1 must reject the empty id before the name is written.
        let req2 = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): {
                            "name": "Should Not Apply",
                            "members/": { "role": "member" }
                        }
                    }
                }),
                "c2".to_string(),
            )],
        };
        let Json(resp2) = handle_jmap_request(State(state.clone()), Json(req2))
            .await
            .unwrap();
        let MethodResponse(_, result2, _) = &resp2.method_responses[0];
        assert!(
            result2["notUpdated"][&space_id].is_object(),
            "combined patch with empty contact_id must be notUpdated"
        );

        // Atomicity check: name must not have been written.
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c3".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        assert_eq!(
            get_resp.method_responses[0].1["list"][0]["name"], "Stable Name",
            "name must not be written when empty contact_id causes notUpdated"
        );
    }

    // ── nie-0kki.1: set_contact_display_name not-found detection ─────────────

    /// ChatContact/set with displayName on an unknown id must return notUpdated,
    /// not updated.  Before the fix, set_contact_display_name returned Ok(())
    /// regardless of rows_affected, so the response falsely reported success.
    #[tokio::test]
    async fn test_contact_set_display_name_unknown_id_returns_not_found() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        "nonexistent-id": { "displayName": "Ghost" }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]["nonexistent-id"].is_object(),
            "unknown id must appear in notUpdated: {result}"
        );
        assert!(
            !result["updated"]
                .as_object()
                .map(|m| m.contains_key("nonexistent-id"))
                .unwrap_or(false),
            "unknown id must not appear in updated"
        );
        assert_eq!(
            result["notUpdated"]["nonexistent-id"]["type"]
                .as_str()
                .unwrap(),
            "notFound",
        );
    }

    // ── nie-0kki.2: empty and unknown-only patch handling ─────────────────────

    /// Empty patch {} is a RFC 8620 §7.1 no-op: the id must appear in updated.
    #[tokio::test]
    async fn test_contact_set_empty_patch_is_noop() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        // Insert a real contact to update.
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { pub_id.clone(): {} }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["updated"]
                .as_object()
                .map(|m| m.contains_key(pub_id.as_str()))
                .unwrap_or(false),
            "empty patch must appear in updated (RFC 8620 §7.1 no-op): {result}"
        );
    }

    /// Patch with only unrecognized keys must appear in notUpdated with
    /// invalidProperties — not silently disappear from both maps.
    #[tokio::test]
    async fn test_contact_set_unknown_keys_returns_invalid_properties() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { pub_id.clone(): { "unknownField": "value" } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .map(|m| m.contains_key(pub_id.as_str()))
                .unwrap_or(false),
            "patch with only unknown keys must appear in notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][pub_id.as_str()]["type"]
                .as_str()
                .unwrap(),
            "invalidProperties",
        );
    }

    /// Mixed patch with one recognized and one unrecognized key must appear in
    /// notUpdated with invalidProperties.  Before the fix, the recognized write
    /// (blocked) would succeed and the id would appear in updated, silently
    /// dropping the unknown key.
    #[tokio::test]
    async fn test_contact_set_mixed_known_unknown_keys_returns_invalid_properties() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { pub_id.clone(): { "blocked": true, "unknownField": "x" } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .map(|m| m.contains_key(pub_id.as_str()))
                .unwrap_or(false),
            "mixed known+unknown keys must appear in notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][pub_id.as_str()]["type"]
                .as_str()
                .unwrap(),
            "invalidProperties",
        );
        // Verify blocked was NOT written (the patch must be rejected atomically).
        let (rows, _) = state
            .store()
            .unwrap()
            .get_contacts(Some(&[pub_id.as_str()]))
            .await
            .unwrap();
        assert!(
            !rows[0].blocked,
            "blocked must remain false — unknown key must reject the whole patch"
        );
    }

    // ── nie-0kki.3: negative position/limit must not panic ───────────────────

    /// ChatContact/query with position=-1 must return invalidArguments, not panic.
    /// Before the fix the negative i64 wrapped on as-usize cast, producing
    /// ids[usize::MAX..small] which panics in Rust slice indexing.
    #[tokio::test]
    async fn test_contact_query_negative_position_returns_invalid_arguments() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/query".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "position": -1_i64,
                    "limit": 3_i64,
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(
            method, "error",
            "negative position must yield error response: {result}"
        );
        assert_eq!(result["type"].as_str().unwrap(), "invalidArguments");
        assert!(
            result["description"]
                .as_str()
                .map(|s| s.contains("position"))
                .unwrap_or(false),
            "error description must name 'position': {result}"
        );
    }

    // ── nie-0kki.4: maxCallsInRequest enforcement ─────────────────────────────

    /// A batch exceeding MAX_CALLS_IN_REQUEST must be rejected with 400.
    #[tokio::test]
    async fn test_handle_jmap_request_rejects_oversized_batch() {
        let state = make_state();
        let calls: Vec<MethodCall> = (0..=MAX_CALLS_IN_REQUEST)
            .map(|i| {
                MethodCall(
                    "unknownMethod".to_string(),
                    serde_json::json!({}),
                    format!("c{i}"),
                )
            })
            .collect();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: calls,
        };
        let result = handle_jmap_request(State(state), Json(req)).await;
        assert!(
            result.is_err(),
            "batch with {} calls must be rejected",
            MAX_CALLS_IN_REQUEST + 1
        );
    }

    /// A batch of exactly MAX_CALLS_IN_REQUEST calls must be accepted.
    #[tokio::test]
    async fn test_handle_jmap_request_accepts_batch_at_limit() {
        let state = make_state();
        let calls: Vec<MethodCall> = (0..MAX_CALLS_IN_REQUEST)
            .map(|i| {
                MethodCall(
                    "unknownMethod".to_string(),
                    serde_json::json!({}),
                    format!("c{i}"),
                )
            })
            .collect();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: calls,
        };
        let result = handle_jmap_request(State(state), Json(req)).await;
        assert!(
            result.is_ok(),
            "batch of {MAX_CALLS_IN_REQUEST} calls must be accepted"
        );
    }

    /// Session object must advertise maxCallsInRequest in the core capability.
    #[tokio::test]
    async fn test_session_advertises_max_calls_in_request() {
        let state = make_state();
        let Json(session) = handle_jmap_session(State(state)).await.unwrap();
        let core_cap = session
            .capabilities
            .get(CAP_CORE)
            .expect("core capability must be present");
        assert!(
            core_cap.get("maxCallsInRequest").is_some(),
            "core capability must include maxCallsInRequest: {core_cap}"
        );
        assert_eq!(
            core_cap["maxCallsInRequest"].as_u64().unwrap(),
            MAX_CALLS_IN_REQUEST as u64,
        );
    }

    // ── nie-0kki.5: contact_changes returns cannotCalculateChanges ────────────

    /// ChatContact/changes must return cannotCalculateChanges when state has
    /// changed, not lie by returning all IDs as "created".
    #[tokio::test]
    async fn test_contact_changes_returns_cannot_calculate_changes() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        // Insert a contact to advance state from "0".
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/changes".to_string(),
                serde_json::json!({"accountId": pub_id, "sinceState": "0"}),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "error", "changed state must return error: {result}");
        assert_eq!(result["type"].as_str().unwrap(), "cannotCalculateChanges");
        assert!(
            result["newState"].is_string(),
            "error must include newState"
        );
    }

    /// ChatContact/changes with sinceState == current state must return empty
    /// change set (not an error).
    #[tokio::test]
    async fn test_contact_changes_no_change_returns_empty() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        // Get current state token.
        let current_state = state
            .store()
            .unwrap()
            .state_token("ChatContact")
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/changes".to_string(),
                serde_json::json!({"accountId": pub_id, "sinceState": current_state}),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(
            method, "ChatContact/changes",
            "unchanged state must return changes object: {result}"
        );
        assert_eq!(result["created"], serde_json::json!([]));
        assert_eq!(result["updated"], serde_json::json!([]));
        assert_eq!(result["removed"], serde_json::json!([]));
    }

    /// ChatContact/query already advertises canCalculateChanges: negative
    /// limit returns invalid arguments.
    #[tokio::test]
    async fn test_contact_query_negative_limit_returns_invalid_arguments() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/query".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "position": 0_i64,
                    "limit": -5_i64,
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(
            method, "error",
            "negative limit must yield error response: {result}"
        );
        assert_eq!(result["type"].as_str().unwrap(), "invalidArguments");
        assert!(
            result["description"]
                .as_str()
                .map(|s| s.contains("limit"))
                .unwrap_or(false),
            "error description must name 'limit': {result}"
        );
    }

    // Regression: Space/set with a non-Object patch value (e.g. a string)
    // must return notUpdated rather than silently dropping the space_id from
    // both updated and notUpdated, which left the client with no signal.
    #[tokio::test]
    async fn test_space_set_non_object_patch_returns_not_updated() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Test Space").await;

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): "not-an-object"
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "Space/set");
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "non-Object patch must appear in notUpdated, got: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidArguments",
            "error type must be invalidArguments"
        );
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "updated must be empty for non-Object patch"
        );
    }

    // Regression: position + limit overflows i64 before the .min() clamp if
    // both are large. In debug builds this panicked the daemon; in release it
    // wrapped to a large usize and returned the wrong slice. Fixed by using
    // saturating_add so the sum clamps to i64::MAX before the usize cast.
    #[tokio::test]
    async fn test_contact_query_large_position_limit_does_not_panic() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        // Insert one contact so the query has something to page over.
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/query".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    // position + limit overflows i64 if added directly.
                    "position": i64::MAX - 1,
                    "limit": i64::MAX - 1,
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        // Must not panic. Response may be an empty page (position beyond end)
        // or an error; either is acceptable — the daemon must survive the input.
        assert!(
            method == "ChatContact/query" || method == "error",
            "unexpected method: {method}, result: {result}"
        );
        if method == "ChatContact/query" {
            // If it succeeded, the result must be a valid (possibly empty) page.
            assert!(
                result["ids"].is_array(),
                "ids must be an array, got: {result}"
            );
        }
    }

    // ── nie-ms2c.1: member-only Space/set patch on nonexistent space ──────────

    /// A members/* patch on a nonexistent space_id must return notFound, not
    /// updated.  Before the fix, update_space_fully skipped the existence check
    /// when name=None && description=None, inserted an orphaned space_member
    /// row, and returned Ok(true).
    #[tokio::test]
    async fn test_space_set_member_only_patch_on_nonexistent_space_returns_not_found() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let fake_space_id = "nonexistent-space-id";
        let contact_id = "b".repeat(64);

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        fake_space_id: { format!("members/{contact_id}"): { "role": "member" } }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][fake_space_id].is_object(),
            "member-only patch on nonexistent space must be notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][fake_space_id]["type"], "notFound",
            "error type must be notFound"
        );
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "updated must be empty"
        );

        // Verify no orphaned space_member row was created.
        let members = state
            .store()
            .unwrap()
            .get_space_members(fake_space_id)
            .await
            .unwrap();
        assert!(
            members.is_empty(),
            "no orphaned space_member rows must exist after notFound: {members:?}"
        );
    }

    // ── nie-ms2c.0: non-object non-null member patch value ───────────────────

    /// Space/set with {"members/abc": 42} must return notUpdated with
    /// invalidArguments, not silently add the member with the "member" role.
    /// Before the fix, validate_member_patch only checked value.is_null(); a
    /// scalar value passed because value.get("role") returns None on non-objects,
    /// defaulting to SpaceRole::Member.
    #[tokio::test]
    async fn test_space_set_member_scalar_value_rejected() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "S").await;
        let contact_id = "b".repeat(64);

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): { format!("members/{contact_id}"): 42 }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "scalar member value must be in notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidArguments",
            "error type must be invalidArguments"
        );
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "updated must be empty"
        );

        // Verify contact_id was NOT added to the space (creator is still a member).
        let members = state
            .store()
            .unwrap()
            .get_space_members(&space_id)
            .await
            .unwrap();
        assert!(
            members.iter().all(|m| m.contact_id != contact_id),
            "contact_id must not be added after rejected patch: {members:?}"
        );
    }

    // ── nie-ms2c.2: empty Space/set patch {} on nonexistent space ────────────

    /// An empty patch {} on a nonexistent space_id must return notFound, not
    /// updated.  Before the fix, update_space_fully returned Ok(true) without
    /// any writes or existence check.
    #[tokio::test]
    async fn test_space_set_empty_patch_on_nonexistent_space_returns_not_found() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let fake_space_id = "nonexistent-space-id-2";

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { fake_space_id: {} }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][fake_space_id].is_object(),
            "empty patch on nonexistent space must be notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][fake_space_id]["type"], "notFound",
            "error type must be notFound"
        );
    }

    // ── nie-ms2c.3: empty ChatContact/set patch {} on nonexistent contact ─────

    /// An empty patch {} on a nonexistent contact id must return notFound, not
    /// updated.  Before the fix, the empty-patch branch in contact_set called
    /// updated.insert without checking whether the contact exists.
    #[tokio::test]
    async fn test_contact_set_empty_patch_on_nonexistent_contact_returns_not_found() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let nonexistent_id = "nonexistent-contact-id";

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { nonexistent_id: {} }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][nonexistent_id].is_object(),
            "empty patch on nonexistent contact must be notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][nonexistent_id]["type"], "notFound",
            "error type must be notFound"
        );
        assert!(
            !result["updated"]
                .as_object()
                .map(|m| m.contains_key(nonexistent_id))
                .unwrap_or(false),
            "nonexistent contact must not appear in updated"
        );
    }

    // ── nie-uf6a.1: contact_set atomicity ────────────────────────────────────

    /// Regression: PATCH {"blocked":true, "displayName":42} must be fully
    /// rejected — blocked must NOT be written even though it is individually
    /// valid.  Before Phase 1 validation was added, set_contact_blocked wrote
    /// blocked=true and then displayName:42 failed the type check, producing
    /// notUpdated while the blocked change had already been persisted (RFC 8620
    /// §7.1 atomicity violation).
    #[tokio::test]
    async fn test_contact_set_blocked_and_bad_displayname_type_is_atomic() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        state
            .store()
            .unwrap()
            .upsert_chat_contact(&pub_id)
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        pub_id.clone(): { "blocked": true, "displayName": 42 }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][pub_id.as_str()].is_object(),
            "bad displayName type must land in notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][pub_id.as_str()]["type"],
            "invalidProperties",
            "error type must be invalidProperties"
        );
        assert!(
            result["updated"]
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(true),
            "updated must be empty — blocked must not have been written"
        );

        // Verify blocked was NOT written to the DB (the whole patch must be atomic).
        let (rows, _) = state
            .store()
            .unwrap()
            .get_contacts(Some(&[pub_id.as_str()]))
            .await
            .unwrap();
        assert!(
            !rows[0].blocked,
            "blocked must remain false after atomicity violation was prevented"
        );
    }

    // ── nie-cp2h.1: contact_set Phase 2 single state bump ────────────────────

    /// A two-field patch ({blocked, displayName}) must increment ChatContact
    /// state exactly once, not once per field.  Before update_contact_fully,
    /// Phase 2 made two separate store calls each bumping state independently;
    /// a concurrent get between the two bumps would see intermediate state.
    #[tokio::test]
    async fn test_contact_set_two_field_patch_bumps_state_once() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let store = state.store().unwrap();
        store.upsert_chat_contact(&pub_id).await.unwrap();
        let state_before = store.state_token("ChatContact").await.unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "ChatContact/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { pub_id.clone(): { "blocked": true, "displayName": "Alice" } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["updated"]
                .as_object()
                .unwrap()
                .contains_key(pub_id.as_str()),
            "two-field patch must succeed: {result}"
        );

        let state_after = store.state_token("ChatContact").await.unwrap();
        // State token is a stringified integer; parse both and compare.
        let before_n: i64 = state_before.parse().unwrap_or(0);
        let after_n: i64 = state_after.parse().unwrap_or(0);
        assert_eq!(
            after_n - before_n,
            1,
            "two-field patch must bump ChatContact state exactly once, not twice (before={state_before}, after={state_after})"
        );
    }

    // ── nie-3c7e.1: Space/changes cannotCalculateChanges ─────────────────────

    /// Space/changes with sinceState != current state must return
    /// cannotCalculateChanges, not a lying created[] list of all current spaces.
    #[tokio::test]
    async fn test_space_changes_returns_cannot_calculate_changes() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        // Create a space to advance state from "0".
        create_test_space(&state, "Space A").await;
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/changes".to_string(),
                serde_json::json!({"accountId": pub_id, "sinceState": "0"}),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(method, "error", "changed state must return error: {result}");
        assert_eq!(
            result["type"].as_str().unwrap(),
            "cannotCalculateChanges",
            "error type must be cannotCalculateChanges"
        );
        assert!(
            result["newState"].is_string(),
            "error must include newState"
        );
    }

    /// Space/changes with sinceState == current state must return empty change
    /// set (not an error).
    #[tokio::test]
    async fn test_space_changes_no_change_returns_empty() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let current_state = state.store().unwrap().state_token("Space").await.unwrap();
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/changes".to_string(),
                serde_json::json!({"accountId": pub_id, "sinceState": current_state}),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(method, result, _) = &resp.method_responses[0];
        assert_eq!(
            method, "Space/changes",
            "unchanged state must return changes object: {result}"
        );
        assert_eq!(result["created"], serde_json::json!([]));
        assert_eq!(result["updated"], serde_json::json!([]));
        assert_eq!(result["destroyed"], serde_json::json!([]));
    }

    // ── nie-3c7e.2: space_set silently drops name/description on wrong type ──

    /// Space/set with {"name": 42} must return notUpdated with invalidProperties,
    /// not silently drop the write and return updated.
    #[tokio::test]
    async fn test_space_set_name_wrong_type_returns_invalid_properties() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Original").await;

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { space_id.clone(): { "name": 42 } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "wrong-type name must be in notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidProperties",
            "error type must be invalidProperties"
        );
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "updated must be empty when name has wrong type"
        );

        // Verify the name was NOT changed (atomicity: no partial write).
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c2".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        assert_eq!(
            get_resp.method_responses[0].1["list"][0]["name"], "Original",
            "name must not change when wrong type is rejected"
        );
    }

    /// Space/set with {"description": []} must return notUpdated with
    /// invalidProperties.  null is valid (clears description); an array is not.
    #[tokio::test]
    async fn test_space_set_description_wrong_type_returns_invalid_properties() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Stable").await;

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { space_id.clone(): { "description": [] } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "wrong-type description must be in notUpdated: {result}"
        );
        assert_eq!(
            result["notUpdated"][&space_id]["type"], "invalidProperties",
            "error type must be invalidProperties"
        );
    }

    /// Atomicity: combined {"name": "New", "description": []} patch must not
    /// write name even though name alone would be valid.
    #[tokio::test]
    async fn test_space_set_valid_name_wrong_description_rejects_whole_patch() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);
        let space_id = create_test_space(&state, "Immutable").await;

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": {
                        space_id.clone(): { "name": "Changed", "description": false }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"][&space_id].is_object(),
            "mixed patch with invalid description must be in notUpdated: {result}"
        );

        // Verify name was NOT written.
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c2".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        assert_eq!(
            get_resp.method_responses[0].1["list"][0]["name"], "Immutable",
            "name must not be written when description type is invalid"
        );
    }

    /// description: null clears the description field.  The oracle is a
    /// follow-up Space/get that verifies the DB value is actually null —
    /// not just that the set response reports success.
    #[tokio::test]
    async fn test_space_set_description_null_clears_description() {
        let state = make_store_state().await;
        let pub_id = "a".repeat(64);

        // Create a space that starts with a non-null description so the clear
        // is a real write, not a vacuous no-op.
        let create_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "create": { "s1": { "name": "HasDesc", "description": "will be cleared" } }
                }),
                "c0".to_string(),
            )],
        };
        let Json(create_resp) = handle_jmap_request(State(state.clone()), Json(create_req))
            .await
            .unwrap();
        let space_id = create_resp.method_responses[0].1["created"]["s1"]["id"]
            .as_str()
            .expect("created space must have id")
            .to_string();

        // Patch description to null.
        let patch_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/set".to_string(),
                serde_json::json!({
                    "accountId": pub_id,
                    "update": { space_id.clone(): { "description": null } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(patch_resp) = handle_jmap_request(State(state.clone()), Json(patch_req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &patch_resp.method_responses[0];
        assert!(
            result["updated"]
                .as_object()
                .unwrap()
                .contains_key(&space_id),
            "description: null must be accepted: {result}"
        );

        // Verify the description is actually null in the DB, not just that the
        // set response claimed success.
        let get_req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Space/get".to_string(),
                serde_json::json!({ "accountId": pub_id, "ids": [space_id.clone()] }),
                "c2".to_string(),
            )],
        };
        let Json(get_resp) = handle_jmap_request(State(state.clone()), Json(get_req))
            .await
            .unwrap();
        assert!(
            get_resp.method_responses[0].1["list"][0]["description"].is_null(),
            "description must be null after null patch: {:?}",
            get_resp.method_responses[0].1["list"][0]
        );
    }

    #[tokio::test]
    async fn test_message_set_update_non_object_patch_rejected() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "hi", "2026-04-24T00:00:00Z")
            .await
            .unwrap();

        // Sending a scalar (42) as the patch value must land in notUpdated, not
        // silently disappear from both updated and notUpdated.
        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": { msg_id.clone(): 42 }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["updated"].as_object().unwrap().is_empty(),
            "scalar patch must not appear in updated"
        );
        assert!(
            result["notUpdated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "scalar patch must appear in notUpdated with invalidArguments"
        );
        assert_eq!(
            result["notUpdated"][msg_id.as_str()]["type"],
            "invalidArguments"
        );
    }

    #[tokio::test]
    async fn test_message_set_update_body_wrong_type_rejected() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(
                &channel_id,
                &"a".repeat(64),
                "original",
                "2026-04-24T00:00:00Z",
            )
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": { msg_id.clone(): { "body": 99 } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "non-string body must be rejected with invalidArguments"
        );
        assert_eq!(
            result["notUpdated"][msg_id.as_str()]["type"],
            "invalidArguments"
        );
        // Body must be unchanged
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        assert_eq!(msgs[0].body, "original");
    }

    #[tokio::test]
    async fn test_message_set_update_deleted_at_wrong_type_rejected() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "text", "2026-04-24T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": { msg_id.clone(): { "deletedAt": true } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "boolean deletedAt must be rejected with invalidArguments"
        );
        assert_eq!(
            result["notUpdated"][msg_id.as_str()]["type"],
            "invalidArguments"
        );
        // Message must not be soft-deleted
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        assert!(
            msgs[0].deleted_at.is_none(),
            "message must not be soft-deleted when deletedAt type is wrong"
        );
    }

    #[tokio::test]
    async fn test_message_set_update_deleted_at_null_rejected() {
        // null would semantically mean "un-delete" which is not implemented.
        // Before this fix, null silently triggered a soft-delete (backwards).
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "text", "2026-04-24T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": { msg_id.clone(): { "deletedAt": null } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "null deletedAt must be rejected (un-delete not implemented)"
        );
        assert_eq!(
            result["notUpdated"][msg_id.as_str()]["type"],
            "invalidArguments"
        );
        // Crucially: message must NOT have been soft-deleted
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        assert!(
            msgs[0].deleted_at.is_none(),
            "null deletedAt must not soft-delete the message"
        );
    }

    #[tokio::test]
    async fn test_message_set_update_reaction_non_object_rejected() {
        // A scalar reaction value (not null and not an object) must be rejected.
        // Before this fix, it would silently create a reaction with emoji="?".
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "hi", "2026-04-24T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": {
                        msg_id.clone(): { "reactions/r1": "not_an_object" }
                    }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "scalar reaction value must be rejected with invalidArguments"
        );
        assert_eq!(
            result["notUpdated"][msg_id.as_str()]["type"],
            "invalidArguments"
        );
        // No reaction must have been stored
        let (msgs, _) = store.get_messages(&[&msg_id]).await.unwrap();
        let reactions: serde_json::Value =
            serde_json::from_str(&msgs[0].reactions).unwrap_or(serde_json::json!({}));
        assert!(
            reactions.as_object().map(|m| m.is_empty()).unwrap_or(true),
            "no reaction must be stored when value type is wrong"
        );
    }

    #[tokio::test]
    async fn test_message_set_update_read_at_wrong_type_rejected() {
        let state = make_store_state().await;
        let channel_id = state.default_channel_id().unwrap().to_string();
        let store = state.store().unwrap();
        let msg_id = store
            .insert_message(&channel_id, &"a".repeat(64), "text", "2026-04-24T00:00:00Z")
            .await
            .unwrap();

        let req = JmapRequest {
            using: vec![CAP_CHAT.to_string()],
            method_calls: vec![MethodCall(
                "Message/set".to_string(),
                serde_json::json!({
                    "accountId": "a".repeat(64),
                    "update": { msg_id.clone(): { "readAt": 123 } }
                }),
                "c1".to_string(),
            )],
        };
        let Json(resp) = handle_jmap_request(State(state.clone()), Json(req))
            .await
            .unwrap();
        let MethodResponse(_, result, _) = &resp.method_responses[0];
        assert!(
            result["notUpdated"]
                .as_object()
                .unwrap()
                .contains_key(msg_id.as_str()),
            "non-string readAt must be rejected with invalidArguments"
        );
        assert_eq!(
            result["notUpdated"][msg_id.as_str()]["type"],
            "invalidArguments"
        );
    }
}
