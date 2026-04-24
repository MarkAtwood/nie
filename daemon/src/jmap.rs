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
use nie_core::messages::ClearMessage;
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
use crate::store::{ChatContactRow, ChatRow, MessageRow, Store};
use crate::token::validate_token_header;
use crate::types::DaemonEvent;

// ── Capability URIs ────────────────────────────────────────────────────────────

pub const CAP_CORE: &str = "urn:ietf:params:jmap:core";
pub const CAP_CHAT: &str = "urn:ietf:params:jmap:chat";

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
    caps.insert(CAP_CORE.to_string(), serde_json::json!({}));
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
async fn session_state_token(state: &DaemonState) -> Result<String, StatusCode> {
    let Some(store) = state.store() else {
        // No store → stable token.
        return Ok("0".to_string());
    };
    // Build a composite token from all tracked types.  If any type changes,
    // the concatenation changes — simple, no hashing needed for a local server.
    let mut parts = Vec::with_capacity(4);
    for type_name in &["ChatContact", "Chat", "Message", "Space"] {
        let tok = store
            .state_token(type_name)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        parts.push(tok);
    }
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

fn server_fail(msg: &str) -> (String, Value) {
    tracing::warn!("JMAP serverFail: {msg}");
    (
        "error".to_string(),
        serde_json::json!({ "type": "serverFail", "description": msg }),
    )
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
    let id_strs: Option<Vec<&str>> = ids_opt
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());

    let state_tok = match store.state_token("ChatContact").await {
        Ok(t) => t,
        Err(e) => return server_fail(&e.to_string()),
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
        Err(e) => server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };

    // Simplified: if sinceState == new_state, no changes.
    // Otherwise, return all current contact IDs as "created".
    let (created, updated): (Vec<String>, Vec<String>) = if since_state == new_state {
        (vec![], vec![])
    } else {
        let ids: Vec<String> = match store.query_contacts(None, None).await {
            Ok(v) => v,
            Err(e) => return server_fail(&e.to_string()),
        };
        (ids, vec![])
    };
    method_ok(
        "ChatContact/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since_state,
            "newState": new_state,
            "hasMoreChanges": false,
            "removed": [],
            "created": created,
            "updated": updated,
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
        Err(e) => return server_fail(&e.to_string()),
    };

    let mut updated: HashMap<String, Value> = HashMap::new();
    let mut not_updated: HashMap<String, Value> = HashMap::new();

    if let Some(Value::Object(updates)) = args.get("update") {
        for (id, patch) in updates {
            let mut any_update = false;

            // blocked field
            if let Some(blocked_val) = patch.get("blocked") {
                if let Some(blocked) = blocked_val.as_bool() {
                    match store.set_contact_blocked(id, blocked).await {
                        Ok(true) => {
                            any_update = true;
                        }
                        Ok(false) => {
                            not_updated.insert(id.clone(), serde_json::json!({"type":"notFound"}));
                            continue;
                        }
                        Err(e) => return server_fail(&e.to_string()),
                    }
                } else {
                    not_updated.insert(
                        id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["blocked"]}),
                    );
                    continue;
                }
            }

            // displayName field
            if let Some(name_val) = patch.get("displayName") {
                let name = if name_val.is_null() {
                    // null clears the display name
                    match store.clear_contact_display_name(id).await {
                        Ok(true) => {}
                        Ok(false) => {
                            not_updated.insert(id.clone(), serde_json::json!({"type":"notFound"}));
                            continue;
                        }
                        Err(e) => return server_fail(&e.to_string()),
                    }
                    updated.insert(id.clone(), Value::Null);
                    continue;
                } else if let Some(s) = name_val.as_str() {
                    match canonicalize_display_name(s) {
                        Ok(n) => n,
                        Err(msg) => {
                            not_updated.insert(
                                id.clone(),
                                serde_json::json!({"type":"invalidProperties","properties":["displayName"],"description":msg}),
                            );
                            continue;
                        }
                    }
                } else {
                    not_updated.insert(
                        id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["displayName"]}),
                    );
                    continue;
                };
                match store.set_contact_display_name(id, &name).await {
                    Ok(()) => {
                        any_update = true;
                    }
                    Err(e) => return server_fail(&e.to_string()),
                }
            }

            if any_update {
                updated.insert(id.clone(), Value::Null);
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
        Err(e) => return server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let ids = match store.query_contacts(presence, blocked).await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
    };
    let total = ids.len() as i64;

    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(total);
    let start = (position as usize).min(ids.len());
    let end = ((position + limit) as usize).min(ids.len());
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let filter = args.get("filter");
    let presence = filter
        .and_then(|f| f.get("presence"))
        .and_then(|v| v.as_str());
    let blocked = filter
        .and_then(|f| f.get("blocked"))
        .and_then(|v| v.as_bool());
    let ids = match store.query_contacts(presence, blocked).await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
    };
    let total = ids.len() as i64;
    // Simplified: if state unchanged → empty; else return all as "added".
    let added: Vec<Value> = if since == new_state {
        vec![]
    } else {
        ids.iter()
            .enumerate()
            .map(|(i, id)| serde_json::json!({"index": i, "id": id}))
            .collect()
    };
    method_ok(
        "ChatContact/queryChanges",
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
        Err(e) => return server_fail(&e.to_string()),
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
        Err(e) => server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let (created, updated): (Vec<String>, Vec<String>) = if since_state == new_state {
        (vec![], vec![])
    } else {
        let ids = match store.get_chats(None).await {
            Ok((list, _)) => list.iter().map(|c| c.id.clone()).collect::<Vec<String>>(),
            Err(e) => return server_fail(&e.to_string()),
        };
        (ids, vec![])
    };
    method_ok(
        "Chat/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since_state,
            "newState": new_state,
            "hasMoreChanges": false,
            "removed": [],
            "created": created,
            "updated": updated,
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let (all_chats, _) = match store.get_chats(None).await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let (spaces, not_found) = match store.get_spaces(id_strs.as_deref()).await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
    };
    let mut list = Vec::new();
    for s in &spaces {
        let members = match store.get_space_members(&s.id).await {
            Ok(m) => m,
            Err(e) => return server_fail(&e.to_string()),
        };
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let (created, updated): (Vec<String>, Vec<String>) = if since == new_state {
        (vec![], vec![])
    } else {
        let ids = match store.query_spaces().await {
            Ok(v) => v,
            Err(e) => return server_fail(&e.to_string()),
        };
        (ids, vec![])
    };
    method_ok(
        "Space/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since,
            "newState": new_state,
            "hasMoreChanges": false,
            "created": created,
            "updated": updated,
            "destroyed": [],
        }),
    )
}

/// Apply a single member patch path ("members/<contact_id>") to a space.
///
/// Returns `Ok(())` if the patch was applied (or the path is not a member
/// path), or `Err(json_error)` with a JMAP error value if validation or the
/// store call fails.  The caller breaks out of the patch loop on `Err`.
async fn apply_member_patch(
    store: &Store,
    space_id: &str,
    path: &str,
    value: &Value,
) -> Result<(), Value> {
    let Some(contact_id) = path.strip_prefix("members/") else {
        return Ok(());
    };
    if value.is_null() {
        // Null value = remove the member from the space.
        store
            .remove_space_member(space_id, contact_id)
            .await
            .map_err(|e| serde_json::json!({"type":"serverFail","description":e.to_string()}))?;
    } else {
        // Non-null value = add/update member with optional role.
        let role = value
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member");
        // Reject unrecognised roles before persisting — an arbitrary string
        // would be stored verbatim and returned in JMAP responses, breaking
        // clients that validate the role enum.
        if !matches!(role, "admin" | "moderator" | "member") {
            return Err(serde_json::json!({
                "type": "invalidArguments",
                "description": "role must be one of: admin, moderator, member"
            }));
        }
        store
            .upsert_space_member_with_role(space_id, contact_id, role)
            .await
            .map_err(|e| serde_json::json!({"type":"serverFail","description":e.to_string()}))?;
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
        Err(e) => return server_fail(&e.to_string()),
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
                Some(n) => n.to_string(),
                None => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"invalidProperties","properties":["name"]}),
                    );
                    continue;
                }
            };
            let description = props
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);
            let id = crate::store::Store::new_id();
            match store
                .create_space_full(&id, &name, description.as_deref(), &account_id)
                .await
            {
                Ok(()) => {
                    created.insert(client_id.clone(), serde_json::json!({ "id": id }));
                }
                Err(e) => {
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"serverFail","description":e.to_string()}),
                    );
                }
            }
        }
    }

    // ── update (patch) ────────────────────────────────────────────────────
    if let Some(Value::Object(updates)) = args.get("update") {
        for (space_id, patch) in updates {
            if let Some(Value::Object(patch_map)) = Some(patch) {
                let mut update_err: Option<Value> = None;
                // Gather simple property updates
                let new_name = patch_map.get("name").and_then(|v| v.as_str());
                let new_desc = patch_map
                    .get("description")
                    .map(|v| if v.is_null() { None } else { v.as_str() })
                    .unwrap_or(None);
                if new_name.is_some() || new_desc.is_some() {
                    match store.update_space_props(space_id, new_name, new_desc).await {
                        Ok(false) => {
                            update_err = Some(serde_json::json!({"type":"notFound"}));
                        }
                        Err(e) => {
                            update_err = Some(
                                serde_json::json!({"type":"serverFail","description":e.to_string()}),
                            );
                        }
                        Ok(true) => {}
                    }
                }
                // Member patch paths: "members/<contact_id>"
                if update_err.is_none() {
                    for (path, value) in patch_map {
                        if let Err(e) = apply_member_patch(store, space_id, path, value).await {
                            update_err = Some(e);
                            break;
                        }
                    }
                }
                if let Some(err) = update_err {
                    not_updated.insert(space_id.clone(), err);
                } else {
                    updated.insert(space_id.clone(), Value::Null);
                }
            }
        }
    }

    // ── destroy ───────────────────────────────────────────────────────────
    if let Some(Value::Array(ids)) = args.get("destroy") {
        for id_val in ids {
            if let Some(id) = id_val.as_str() {
                match store.delete_space(id).await {
                    Ok(true) => destroyed.push(Value::String(id.to_string())),
                    Ok(false) => {
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type":"notFound"}));
                    }
                    Err(e) => {
                        not_destroyed.insert(
                            id.to_string(),
                            serde_json::json!({"type":"serverFail","description":e.to_string()}),
                        );
                    }
                }
            }
        }
    }

    let new_state = match store.state_token("Space").await {
        Ok(t) => t,
        Err(e) => return server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let ids = match store.query_spaces().await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let ids = match store.query_spaces().await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
    };
    let total = ids.len() as i64;
    let added: Vec<Value> = if since == new_state {
        vec![]
    } else {
        ids.into_iter()
            .enumerate()
            .map(|(i, id)| serde_json::json!({ "index": i as i64, "id": id }))
            .collect()
    };
    method_ok(
        "Space/queryChanges",
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
    match store.use_space_invite_code(&code, &account_id).await {
        Ok(Some(space_id)) => method_ok("Space/join", serde_json::json!({ "spaceId": space_id })),
        Ok(None) => (
            "error".to_string(),
            serde_json::json!({
                "type": "notFound",
                "description": "invite code not found or expired"
            }),
        ),
        Err(e) => server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
    };
    match store.get_space_invites(id_strs.as_deref()).await {
        Ok((invites, not_found)) => method_ok(
            "SpaceInvite/get",
            serde_json::json!({
                "accountId": account_id,
                "state": state_tok,
                "list": invites.iter().map(space_invite_to_json).collect::<Vec<_>>(),
                "notFound": not_found,
            }),
        ),
        Err(e) => server_fail(&e.to_string()),
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
        Err(e) => return server_fail(&e.to_string()),
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
            let id = crate::store::Store::new_id();
            // Generate a short random invite code (8 chars of ULID entropy)
            let code = Ulid::new().to_string()[..8].to_uppercase();
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
                    not_created.insert(
                        client_id.clone(),
                        serde_json::json!({"type":"serverFail","description":e.to_string()}),
                    );
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

    // ── destroy: not supported ────────────────────────────────────────────
    if let Some(Value::Array(ids)) = args.get("destroy") {
        for id_val in ids {
            if let Some(id) = id_val.as_str() {
                not_destroyed.insert(
                    id.to_string(),
                    serde_json::json!({"type":"forbidden","description":"SpaceInvite objects cannot be destroyed"}),
                );
            }
        }
    }

    let new_state = match store.state_token("SpaceInvite").await {
        Ok(t) => t,
        Err(e) => return server_fail(&e.to_string()),
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
            "destroyed": [],
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
    let ids: Vec<String> = match args.get("ids") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return method_error("invalidArguments"),
    };
    let id_strs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let state_tok = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return server_fail(&e.to_string()),
    };
    match store.get_messages(&id_strs).await {
        Ok((list, not_found)) => method_ok(
            "Message/get",
            serde_json::json!({
                "accountId": account_id,
                "state": state_tok,
                "list": list.iter().map(message_to_json).collect::<Vec<_>>(),
                "notFound": not_found,
            }),
        ),
        Err(e) => server_fail(&e.to_string()),
    }
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
        Err(e) => return server_fail(&e.to_string()),
    };
    // Simplified: if unchanged → empty; else return all message IDs as "created".
    let created = if since_state == new_state {
        vec![]
    } else {
        // We don't have a cheap "all message ids" query — use default channel only.
        match state.default_channel_id() {
            Some(chan) => match store.query_messages(chan, 0, i64::MAX).await {
                Ok(ids) => ids,
                Err(e) => return server_fail(&e.to_string()),
            },
            None => vec![],
        }
    };
    method_ok(
        "Message/changes",
        serde_json::json!({
            "accountId": account_id,
            "oldState": since_state,
            "newState": new_state,
            "hasMoreChanges": false,
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
        Err(e) => return server_fail(&e.to_string()),
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

            // Optional fields
            let reply_to = props
                .get("replyTo")
                .and_then(|v| v.as_str())
                .map(String::from);
            let thread_root_id = props
                .get("threadRootId")
                .and_then(|v| v.as_str())
                .map(String::from);
            let expires_at = props
                .get("senderExpiresAt")
                .and_then(|v| v.as_str())
                .map(String::from);
            let burn_on_read = props
                .get("burnOnRead")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

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
                Err(e) => return server_fail(&e.to_string()),
            };

            // Encrypt and send via relay if MLS client available.
            if let Some(mls) = state.mls_client().await {
                let clear = ClearMessage::Chat { text: body };
                let payload_bytes = serde_json::to_vec(&clear).unwrap();
                let encrypted = mls.lock().await.encrypt(&payload_bytes);
                match encrypted {
                    Ok(cipher) => {
                        if let Some(tx) = state.relay_tx().await {
                            let rpc = JsonRpcRequest::new(
                                next_request_id(),
                                rpc_methods::BROADCAST,
                                BroadcastParams { payload: cipher },
                            )
                            .unwrap();
                            let _ = tx.send(rpc).await;
                        }
                    }
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
            if let Some(Value::Object(patch_map)) = Some(patch) {
                let mut update_err: Option<Value> = None;
                for (path, value) in patch_map {
                    if let Some(reaction_id) = path.strip_prefix("reactions/") {
                        let res = if value.is_null() {
                            store.remove_message_reaction(msg_id, reaction_id).await
                        } else {
                            let emoji = value.get("emoji").and_then(|v| v.as_str()).unwrap_or("?");
                            let sent_at = value
                                .get("sentAt")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            store
                                .set_message_reaction(msg_id, reaction_id, emoji, sent_at)
                                .await
                        };
                        match res {
                            Ok(false) => {
                                update_err = Some(serde_json::json!({"type":"notFound"}));
                                break;
                            }
                            Err(e) => {
                                update_err = Some(
                                    serde_json::json!({"type":"serverFail","description":e.to_string()}),
                                );
                                break;
                            }
                            Ok(true) => {}
                        }
                    } else if path == "body" {
                        if let Some(new_body) = value.as_str() {
                            match store.edit_message_body(msg_id, new_body).await {
                                Ok(false) => {
                                    update_err = Some(serde_json::json!({"type":"notFound"}));
                                    break;
                                }
                                Err(e) => {
                                    update_err = Some(
                                        serde_json::json!({"type":"serverFail","description":e.to_string()}),
                                    );
                                    break;
                                }
                                Ok(true) => {}
                            }
                        }
                    } else if path == "deletedAt" {
                        if value.is_string() || value.is_null() {
                            match store.soft_delete_message(msg_id, false).await {
                                Ok(false) => {
                                    update_err = Some(serde_json::json!({"type":"notFound"}));
                                    break;
                                }
                                Err(e) => {
                                    update_err = Some(
                                        serde_json::json!({"type":"serverFail","description":e.to_string()}),
                                    );
                                    break;
                                }
                                Ok(true) => {}
                            }
                        }
                    } else if path == "readAt" {
                        if let Some(ts) = value.as_str() {
                            if let Err(e) = store.read_message(msg_id, ts).await {
                                update_err = Some(
                                    serde_json::json!({"type":"serverFail","description":e.to_string()}),
                                );
                                break;
                            }
                        }
                    }
                    // Unknown patch path: ignore (permissive)
                }
                if let Some(err) = update_err {
                    not_updated.insert(msg_id.clone(), err);
                } else {
                    updated.insert(msg_id.clone(), serde_json::json!(null));
                }
            }
        }
    }

    // ── destroy ─────────────────────────────────────────────────────────────
    if let Some(Value::Array(ids)) = args.get("destroy") {
        for id_val in ids {
            if let Some(id) = id_val.as_str() {
                match store.hard_delete_message(id).await {
                    Ok(true) => destroyed.push(Value::String(id.to_string())),
                    Ok(false) => {
                        not_destroyed
                            .insert(id.to_string(), serde_json::json!({"type":"notFound"}));
                    }
                    Err(e) => {
                        not_destroyed.insert(
                            id.to_string(),
                            serde_json::json!({"type":"serverFail","description":e.to_string()}),
                        );
                    }
                }
            }
        }
    }

    let new_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return server_fail(&e.to_string()),
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
            return method_ok(
                "error",
                serde_json::json!({
                    "type": "unsupportedFilter",
                    "description": "chatId filter is required"
                }),
            )
        }
    };

    let query_state = match store.state_token("Message").await {
        Ok(t) => t,
        Err(e) => return server_fail(&e.to_string()),
    };

    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(256);
    let total = match store.count_messages_in_chat(&chat_id).await {
        Ok(n) => n,
        Err(e) => return server_fail(&e.to_string()),
    };
    let ids = match store.query_messages(&chat_id, position, limit).await {
        Ok(v) => v,
        Err(e) => return server_fail(&e.to_string()),
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
            return method_ok(
                "error",
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
        Err(e) => return server_fail(&e.to_string()),
    };
    let total = match store.count_messages_in_chat(&chat_id).await {
        Ok(n) => n,
        Err(e) => return server_fail(&e.to_string()),
    };
    let added: Vec<Value> = if since == new_state {
        vec![]
    } else {
        let ids = match store.query_messages(&chat_id, 0, i64::MAX).await {
            Ok(v) => v,
            Err(e) => return server_fail(&e.to_string()),
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
pub async fn handle_jmap_upload(
    State(state): State<DaemonState>,
    Path(account_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if account_id != state.my_pub_id() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

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
            ([(header::CONTENT_TYPE, content_type)], data).into_response()
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
        DaemonEvent::MessageReceived { .. } => "Message",
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
        store.create_space(space_id, "test").await.unwrap();
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
            result["updated"][&msg_id].is_null(),
            "updated entry must be null on success"
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
        assert_eq!(msgs[0].expires_at.as_deref(), Some("2026-01-01T00:00:00Z"));

        // Run the reaper — should hard-delete this message (past expiry)
        let deleted = store.hard_delete_expired_messages().await.unwrap();
        assert_eq!(deleted, 1);
        let (found, _) = store.get_messages(&[&msg_id]).await.unwrap();
        assert!(
            found.is_empty(),
            "expired message must be hard-deleted by reaper"
        );
    }
}
