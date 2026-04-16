use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::state::AppState;
use crate::store::InvoiceRow;
use nie_core::auth::{new_challenge, verify_challenge};
use nie_core::protocol::{
    rpc_errors, rpc_methods, AuthenticateParams, AuthenticateResult, BroadcastParams,
    BroadcastResult, ChallengeParams, DeliverParams, DirectoryListParams, GetHpkeKeyParams,
    GetHpkeKeyResult, GetKeyPackageParams, GetKeyPackageResult, GroupAddParams, GroupCreateParams,
    GroupCreateResult, GroupDeliverParams, GroupInfo, GroupLeaveParams, GroupListResult,
    GroupSendParams, GroupSendResult, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    KeyPackageReadyParams, OkResult, PublishHpkeKeyParams, PublishKeyPackageParams,
    SealedBroadcastParams, SealedDeliverParams, SealedWhisperDeliverParams, SealedWhisperParams,
    SetNicknameParams, SubscribeInvoiceResult, SubscribeRequestParams, UserInfo, UserJoinedParams,
    UserLeftParams, UserNicknameParams, WhisperDeliverParams, WhisperParams,
};

/// Maximum WebSocket message size.  Chat payloads are small; 1 MiB leaves
/// room for MLS overhead while preventing broadcast amplification DoS where
/// one sender forces O(N × payload) allocation across all connected clients.
const MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MiB

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(|socket| handle(socket, state))
}

async fn handle(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    // --- Auth handshake ---
    let nonce = new_challenge();

    // serde_json::to_string on a derived Serialize cannot fail
    let challenge_json = serde_json::to_string(
        &JsonRpcNotification::new(
            rpc_methods::CHALLENGE,
            ChallengeParams {
                nonce: nonce.clone(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    if sink
        .send(Message::Text(challenge_json.into()))
        .await
        .is_err()
    {
        return;
    }

    // Receive the Authenticate request
    let text = match stream.next().await {
        Some(Ok(Message::Text(t))) => t,
        Some(Ok(Message::Close(_))) | None => return,
        _ => {
            send_error_response(
                &mut sink,
                0,
                rpc_errors::INVALID_REQUEST,
                "expected text frame",
            )
            .await;
            return;
        }
    };

    let req: JsonRpcRequest = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(_) => {
            send_error_response(&mut sink, 0, rpc_errors::PARSE_ERROR, "parse error").await;
            return;
        }
    };

    if req.method != rpc_methods::AUTHENTICATE {
        send_error_response(
            &mut sink,
            req.id,
            rpc_errors::NOT_AUTHENTICATED,
            "authenticate first",
        )
        .await;
        return;
    }

    let params: AuthenticateParams = match req
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            send_error_response(
                &mut sink,
                req.id,
                rpc_errors::INVALID_REQUEST,
                "invalid authenticate params",
            )
            .await;
            return;
        }
    };

    let pub_id = match verify_challenge(&params.pub_key, &nonce, &params.signature) {
        Ok(id) => id,
        Err(e) => {
            send_error_response(
                &mut sink,
                req.id,
                rpc_errors::AUTH_FAILED,
                &format!("auth failed: {e}"),
            )
            .await;
            return;
        }
    };

    info!("authed: {pub_id}");

    let subscription_expires = match state.inner.store.subscription_expiry(&pub_id.0).await {
        Ok(v) => v,
        Err(e) => {
            error!("subscription_expiry DB error for {pub_id}: {e}");
            send_error_response(
                &mut sink,
                req.id,
                rpc_errors::INTERNAL_ERROR,
                "internal error",
            )
            .await;
            return;
        }
    };

    // Shared subscription flag.  Starts from the DB value at connect time.
    // Updated to true by the write task when a subscription_active notification
    // is forwarded to the client, so SEND/BROADCAST do not require a reconnect
    // to recognize a subscription that was paid during the current session.
    let subscribed_flag = Arc::new(AtomicBool::new(subscription_expires.is_some()));

    // Register (or refresh) this user in the persistent directory.
    if let Err(e) = state.inner.store.register_user(&pub_id.0).await {
        error!("failed to register user {pub_id}: {e}");
        send_error_response(
            &mut sink,
            req.id,
            rpc_errors::INTERNAL_ERROR,
            "internal error",
        )
        .await;
        return;
    }

    // Set up per-client channel before building the directory so the new
    // client appears as online in the list we send them.
    let (client_tx, mut client_rx) = mpsc::channel::<String>(64);
    state.connect(&pub_id, client_tx.clone());

    // Send AuthOk response (reply to the authenticate request)
    // serde_json::to_string on a derived Serialize cannot fail
    let auth_ok = serde_json::to_string(
        &JsonRpcResponse::success(
            req.id,
            AuthenticateResult {
                pub_id: pub_id.0.clone(),
                subscription_expires,
            },
        )
        .unwrap(),
    )
    .unwrap();
    if sink.send(Message::Text(auth_ok.into())).await.is_err() {
        state.disconnect(&pub_id);
        return;
    }

    // Build and send DirectoryList to the newly connected client.
    // SCALE NOTE: all_users() is a full table scan + sort on every connect.
    // At a few hundred users this is invisible (<1 ms).  At tens of thousands
    // of persistent users, consider caching the directory in AppState and
    // invalidating on write, or paginating DirectoryList.  Do not optimize
    // prematurely — benchmark first.
    let all_users = match state.inner.store.all_users().await {
        Ok(v) => v,
        Err(e) => {
            error!("all_users DB error for {pub_id}: {e}");
            state.disconnect(&pub_id);
            return;
        }
    };
    // Grab this user's nickname (may be set from a previous session).
    let my_nickname = all_users
        .iter()
        .find(|(id, _)| id == &pub_id.0)
        .and_then(|(_, n)| n.clone());
    let (mut online, offline): (Vec<UserInfo>, Vec<UserInfo>) = all_users
        .into_iter()
        .map(|(id, nickname)| {
            // sequence is filled after partitioning; offline entries get 0.
            UserInfo {
                pub_id: id,
                nickname,
                sequence: 0,
            }
        })
        .partition(|u| state.inner.clients.contains_key(u.pub_id.as_str()));
    // Sort online users by session connection order (lowest sequence = admin).
    // This uses the monotonic connection_counter, not historical first_seen,
    // so the first client to connect in the current relay session is always admin.
    online.sort_by_key(|u| state.connection_seq(&u.pub_id));
    // Stamp each online entry with its sequence number so clients can maintain
    // sorted order when handling subsequent UserJoined events.
    for u in &mut online {
        u.sequence = state.connection_seq(&u.pub_id);
    }

    // serde_json::to_string on a derived Serialize cannot fail
    let dir_json = serde_json::to_string(
        &JsonRpcNotification::new(
            rpc_methods::DIRECTORY_LIST,
            DirectoryListParams { online, offline },
        )
        .unwrap(),
    )
    .unwrap();
    if sink.send(Message::Text(dir_json.into())).await.is_err() {
        state.disconnect(&pub_id);
        return;
    }

    // Tell everyone else this user has arrived (include nickname if already set).
    // Broadcast includes this client's connection_seq so peers can maintain their
    // online list in sorted order regardless of UserJoined event arrival order.
    // serde_json::to_string on a derived Serialize cannot fail
    let joined_json = serde_json::to_string(
        &JsonRpcNotification::new(
            rpc_methods::USER_JOINED,
            UserJoinedParams {
                pub_id: pub_id.0.clone(),
                nickname: my_nickname,
                sequence: state.connection_seq(&pub_id.0),
            },
        )
        .unwrap(),
    )
    .unwrap();
    state.broadcast(Some(&pub_id.0), joined_json).await;

    // Shared flag: set to true each time a Pong arrives from the client.
    // Starts true so the first ping interval does not disconnect immediately.
    let pong_received = Arc::new(AtomicBool::new(true));
    let pong_write = pong_received.clone();

    // Clone of subscribed_flag for the write task so it can update the flag
    // when it forwards a subscription_active notification to the client.
    let subscribed_flag_write = Arc::clone(&subscribed_flag);

    let keepalive_secs = state.inner.keepalive_secs;
    let pub_id_ping = pub_id.clone();

    // Writer task: pull from client_rx, write to ws sink.
    // Also sends a Ping every keepalive_secs seconds and disconnects if the
    // client stops responding (no Pong arrives before the next Ping).
    let write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(keepalive_secs));
        // MissedTickBehavior::Delay: if we're busy, wait a full interval before
        // the next ping rather than firing a burst of missed ticks.
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate first tick so the first ping is sent after one
        // full interval, not immediately on connect.
        ping_interval.tick().await;

        loop {
            tokio::select! {
                msg = client_rx.recv() => {
                    match msg {
                        Some(json) => {
                            // Update the subscription flag before sending so the
                            // read loop can use the flag on the very next message
                            // without waiting for the socket round-trip.
                            if json.contains(r#""method":"subscription_active""#) {
                                subscribed_flag_write.store(true, Ordering::Relaxed);
                            }
                            // Delivery jitter: uniform 0–50 ms per-message random delay
                            // to obscure per-client timing from a relay-level observer.
                            // Kept ≤50 ms so the write task can process at ≥20 msg/s,
                            // well above normal human-speed message rates.
                            let delay_ms = rand::random::<u64>() % 51;
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            if sink.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = ping_interval.tick() => {
                    // If the previous Ping was not acked by now, the client is gone.
                    if !pong_write.swap(false, Ordering::Relaxed) {
                        warn!("keepalive timeout: no pong from {pub_id_ping}, disconnecting");
                        break;
                    }
                    if sink.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Drain any offline messages queued while this client was disconnected.
    // client_tx is ready (write_task is already spawned above), so messages
    // sent here will be flushed to the socket immediately.
    let queued = match state.inner.store.drain(&pub_id.0).await {
        Ok(msgs) => msgs,
        Err(e) => {
            warn!("drain failed for {pub_id}: {e}");
            vec![]
        }
    };
    for msg in queued {
        client_tx.send(msg).await.ok();
    }

    // Main read loop
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(Message::Text(t)) => {
                let req: JsonRpcRequest = match serde_json::from_str(&t) {
                    Ok(r) => r,
                    Err(_) => {
                        warn!("unparseable JSON-RPC from {pub_id}");
                        // Cannot send an error response — no id available.
                        continue;
                    }
                };

                if req.version != "2.0" {
                    let err = serde_json::to_string(&JsonRpcResponse::error(
                        req.id,
                        rpc_errors::INVALID_REQUEST,
                        "jsonrpc must be 2.0",
                    ))
                    .unwrap();
                    client_tx.send(err).await.ok();
                    continue;
                }

                match req.method.as_str() {
                    rpc_methods::BROADCAST => {
                        let params: BroadcastParams = match deserialize_params(req.params.as_ref())
                        {
                            Ok(p) => p,
                            Err(_) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INVALID_REQUEST,
                                    "invalid params",
                                )
                                .await;
                                continue;
                            }
                        };
                        if state.inner.require_subscription
                            && !subscribed_flag.load(Ordering::Relaxed)
                        {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::NOT_AUTHENTICATED,
                                "an active subscription is required to send messages",
                            )
                            .await;
                            continue;
                        }
                        let message_id = Uuid::new_v4().to_string();
                        // SECURITY: `from` is always relay-set from authenticated pub_id,
                        // never taken from client params.
                        // serde_json::to_string on a derived Serialize cannot fail
                        let deliver_json = serde_json::to_string(
                            &JsonRpcNotification::new(
                                rpc_methods::DELIVER,
                                DeliverParams {
                                    from: pub_id.0.clone(),
                                    payload: params.payload,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        state.broadcast(Some(&pub_id.0), deliver_json).await;
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, BroadcastResult { message_id })
                                .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::SEALED_BROADCAST => {
                        let params: SealedBroadcastParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        if state.inner.require_subscription
                            && !subscribed_flag.load(Ordering::Relaxed)
                        {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::NOT_AUTHENTICATED,
                                "an active subscription is required to send messages",
                            )
                            .await;
                            continue;
                        }
                        let message_id = Uuid::new_v4().to_string();
                        // SEALED SENDER: relay fans out opaque bytes with NO `from` field.
                        // Sender identity is hidden inside the encrypted sealed bytes.
                        // The relay never inspects params.sealed — it is opaque by construction.
                        // serde_json::to_string on a derived Serialize cannot fail
                        let deliver_json = serde_json::to_string(
                            &JsonRpcNotification::new(
                                rpc_methods::SEALED_DELIVER,
                                SealedDeliverParams {
                                    sealed: params.sealed,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        state.broadcast(Some(&pub_id.0), deliver_json).await;
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, BroadcastResult { message_id })
                                .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::SET_NICKNAME => {
                        let params: SetNicknameParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        let nickname = params.nickname.trim().to_string();
                        if nickname.is_empty() || nickname.chars().count() > 32 {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INVALID_REQUEST,
                                "nickname must be 1–32 characters",
                            )
                            .await;
                            continue;
                        }
                        match state
                            .inner
                            .store
                            .try_set_nickname(&pub_id.0, &nickname)
                            .await
                        {
                            Ok(true) => {
                                // Broadcast to everyone including the sender.
                                // serde_json::to_string on a derived Serialize cannot fail
                                let notif = serde_json::to_string(
                                    &JsonRpcNotification::new(
                                        rpc_methods::USER_NICKNAME,
                                        UserNicknameParams {
                                            pub_id: pub_id.0.clone(),
                                            nickname,
                                        },
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                                state.broadcast(None, notif).await;
                                let ok = serde_json::to_string(
                                    &JsonRpcResponse::success(req.id, OkResult { ok: true })
                                        .unwrap(),
                                )
                                .unwrap();
                                client_tx.send(ok).await.ok();
                            }
                            Ok(false) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::NICKNAME_TAKEN,
                                    "nickname already set and cannot be changed",
                                )
                                .await;
                            }
                            Err(e) => {
                                error!("try_set_nickname error: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                            }
                        }
                    }

                    rpc_methods::PUBLISH_KEY_PACKAGE => {
                        let params: PublishKeyPackageParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        match state
                            .inner
                            .store
                            .save_key_package(&pub_id.0, &params.data)
                            .await
                        {
                            Ok(()) => {
                                // Broadcast KeyPackageReady AFTER the write succeeds.
                                // This creates a happens-before edge: any GetKeyPackage sent
                                // in response to this notification is guaranteed to find the
                                // stored package.  Fixes the race where admin sent GetKeyPackage
                                // on UserJoined before the new member's PublishKeyPackage arrived.
                                // serde_json::to_string on a derived Serialize cannot fail
                                let notif = serde_json::to_string(
                                    &JsonRpcNotification::new(
                                        rpc_methods::KEY_PACKAGE_READY,
                                        KeyPackageReadyParams {
                                            pub_id: pub_id.0.clone(),
                                        },
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                                state.broadcast(None, notif).await;
                                let ok = serde_json::to_string(
                                    &JsonRpcResponse::success(req.id, OkResult { ok: true })
                                        .unwrap(),
                                )
                                .unwrap();
                                client_tx.send(ok).await.ok();
                            }
                            Err(e) => {
                                error!("save_key_package for {pub_id}: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                            }
                        }
                    }

                    rpc_methods::GET_KEY_PACKAGE => {
                        let params: GetKeyPackageParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        let data = match state.inner.store.get_key_package(&params.pub_id).await {
                            Ok(v) => v,
                            Err(e) => {
                                error!("get_key_package DB error for {}: {e}", params.pub_id);
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        };
                        // serde_json::to_string on a derived Serialize cannot fail
                        let resp = serde_json::to_string(
                            &JsonRpcResponse::success(
                                req.id,
                                GetKeyPackageResult {
                                    pub_id: params.pub_id,
                                    data,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(resp).await.ok();
                    }

                    rpc_methods::PUBLISH_HPKE_KEY => {
                        let params: PublishHpkeKeyParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        // Validate: a Curve25519 / X25519 public key is exactly 32 bytes.
                        if params.public_key.len() != 32 {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INVALID_REQUEST,
                                "public_key must be 32 bytes",
                            )
                            .await;
                            continue;
                        }
                        match state
                            .inner
                            .store
                            .save_hpke_key(&pub_id.0, &params.public_key)
                            .await
                        {
                            Ok(()) => {
                                // No broadcast: peers fetch on demand via GET_HPKE_KEY.
                                // serde_json::to_string on a derived Serialize cannot fail
                                let ok = serde_json::to_string(
                                    &JsonRpcResponse::success(req.id, OkResult { ok: true })
                                        .unwrap(),
                                )
                                .unwrap();
                                client_tx.send(ok).await.ok();
                            }
                            Err(e) => {
                                error!("save_hpke_key for {pub_id}: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                            }
                        }
                    }

                    rpc_methods::GET_HPKE_KEY => {
                        let params: GetHpkeKeyParams = match deserialize_params(req.params.as_ref())
                        {
                            Ok(p) => p,
                            Err(_) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INVALID_REQUEST,
                                    "invalid params",
                                )
                                .await;
                                continue;
                            }
                        };
                        // Unauthenticated lookup: no subscription check required.
                        // Any connected peer may fetch another user's HPKE public key.
                        let key_data = match state.inner.store.get_hpke_key(&params.pub_id).await {
                            Ok(v) => v,
                            Err(e) => {
                                error!("get_hpke_key DB error for {}: {e}", params.pub_id);
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        };
                        // serde_json::to_string on a derived Serialize cannot fail
                        let resp = serde_json::to_string(
                            &JsonRpcResponse::success(
                                req.id,
                                GetHpkeKeyResult {
                                    pub_id: params.pub_id,
                                    public_key: key_data,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(resp).await.ok();
                    }

                    rpc_methods::WHISPER => {
                        let params: WhisperParams = match deserialize_params(req.params.as_ref()) {
                            Ok(p) => p,
                            Err(_) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INVALID_REQUEST,
                                    "invalid params",
                                )
                                .await;
                                continue;
                            }
                        };
                        // Route opaque bytes to one specific connected user.
                        // The relay never inspects the payload (MLS Welcome or other control msg).
                        // `from` in the outgoing WhisperDeliver is set by the relay from the
                        // authenticated pub_id — not taken from the incoming message — so sender
                        // spoofing is structurally impossible here.
                        // serde_json::to_string on a derived Serialize cannot fail
                        let notif = serde_json::to_string(
                            &JsonRpcNotification::new(
                                rpc_methods::WHISPER_DELIVER,
                                WhisperDeliverParams {
                                    from: pub_id.0.clone(),
                                    payload: params.payload,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        let delivered = state.deliver_live(&params.to, notif.clone()).await;
                        if !delivered {
                            if let Err(e) = state.inner.store.enqueue(&params.to, &notif).await {
                                warn!("whisper enqueue failed for {}: {e}", params.to);
                            }
                        }
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, OkResult { ok: true }).unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::SEALED_WHISPER => {
                        let params: SealedWhisperParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        // SEALED SENDER: relay forwards opaque bytes to `to` with NO `from` field.
                        // Sender identity is hidden inside the encrypted sealed bytes.
                        // The relay never inspects params.sealed — it is opaque by construction.
                        // serde_json::to_string on a derived Serialize cannot fail
                        let notif = serde_json::to_string(
                            &JsonRpcNotification::new(
                                rpc_methods::SEALED_WHISPER_DELIVER,
                                SealedWhisperDeliverParams {
                                    to: params.to.clone(),
                                    sealed: params.sealed,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        let delivered = state.deliver_live(&params.to, notif.clone()).await;
                        if !delivered {
                            if let Err(e) = state.inner.store.enqueue(&params.to, &notif).await {
                                warn!("sealed_whisper enqueue failed for {}: {e}", params.to);
                            }
                        }
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, OkResult { ok: true }).unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::GROUP_CREATE => {
                        let params: GroupCreateParams =
                            match deserialize_params(req.params.as_ref()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_REQUEST,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        if state.inner.require_subscription
                            && !subscribed_flag.load(Ordering::Relaxed)
                        {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::NOT_AUTHENTICATED,
                                "an active subscription is required to create groups",
                            )
                            .await;
                            continue;
                        }
                        let group_id = Uuid::new_v4().to_string();
                        if let Err(e) = state
                            .inner
                            .store
                            .create_group(&group_id, &pub_id.0, &params.name)
                            .await
                        {
                            error!("create_group for {pub_id}: {e}");
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INTERNAL_ERROR,
                                "internal error",
                            )
                            .await;
                            continue;
                        }
                        if let Err(e) = state
                            .inner
                            .store
                            .add_group_member(&group_id, &pub_id.0)
                            .await
                        {
                            error!("add_group_member (creator) for {pub_id}: {e}");
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INTERNAL_ERROR,
                                "internal error",
                            )
                            .await;
                            continue;
                        }
                        let name = params.name;
                        // serde_json::to_string on a derived Serialize cannot fail
                        let resp = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, GroupCreateResult { group_id, name })
                                .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(resp).await.ok();
                    }

                    rpc_methods::GROUP_ADD => {
                        let params: GroupAddParams =
                            match serde_json::from_value(req.params.unwrap_or_default()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_PARAMS,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };

                        // Validate member_pub_id is exactly 64 lowercase hex chars.
                        if params.member_pub_id.len() != 64
                            || !params
                                .member_pub_id
                                .chars()
                                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
                        {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INVALID_PARAMS,
                                "invalid pub_id format",
                            )
                            .await;
                            continue;
                        }

                        // Group must exist.
                        let group_row = match state.inner.store.get_group(&params.group_id).await {
                            Ok(Some(g)) => g,
                            Ok(None) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::GROUP_NOT_FOUND,
                                    "group not found",
                                )
                                .await;
                                continue;
                            }
                            Err(e) => {
                                error!("get_group failed: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        };

                        // Caller must be a member.
                        match state
                            .inner
                            .store
                            .is_group_member(&params.group_id, &pub_id.0)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::NOT_A_MEMBER,
                                    "not a member",
                                )
                                .await;
                                continue;
                            }
                            Err(e) => {
                                error!("is_group_member failed: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        }

                        // Add member (idempotent).
                        if let Err(e) = state
                            .inner
                            .store
                            .add_group_member(&params.group_id, &params.member_pub_id)
                            .await
                        {
                            error!("add_group_member failed: {e}");
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INTERNAL_ERROR,
                                "internal error",
                            )
                            .await;
                            continue;
                        }

                        // Notify new member: GROUP_DELIVER with group name as payload.
                        // `from` is relay-set from authenticated pub_id — never from params.
                        // serde_json::to_string on a derived Serialize cannot fail
                        let notif = serde_json::to_string(
                            &JsonRpcNotification::new(
                                rpc_methods::GROUP_DELIVER,
                                GroupDeliverParams {
                                    from: pub_id.0.clone(),
                                    group_id: params.group_id.clone(),
                                    payload: group_row.name.into_bytes(),
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        let delivered = state
                            .deliver_live(&params.member_pub_id, notif.clone())
                            .await;
                        if !delivered {
                            if let Err(e) = state
                                .inner
                                .store
                                .enqueue(&params.member_pub_id, &notif)
                                .await
                            {
                                warn!(
                                    "group_add notify enqueue failed for {}: {e}",
                                    params.member_pub_id
                                );
                            }
                        }

                        // serde_json::to_string on a derived Serialize cannot fail
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, OkResult { ok: true }).unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::GROUP_LIST => {
                        let groups = match state.inner.store.list_groups_for_user(&pub_id.0).await {
                            Ok(v) => v,
                            Err(e) => {
                                error!("list_groups_for_user for {pub_id}: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        };
                        let mut group_infos: Vec<GroupInfo> = Vec::with_capacity(groups.len());
                        for g in groups {
                            let member_count = state
                                .inner
                                .store
                                .member_count(&g.group_id)
                                .await
                                .unwrap_or(0);
                            group_infos.push(GroupInfo {
                                group_id: g.group_id,
                                name: g.name,
                                member_count,
                                created_at: g.created_at,
                            });
                        }
                        // serde_json::to_string on a derived Serialize cannot fail
                        let resp = serde_json::to_string(
                            &JsonRpcResponse::success(
                                req.id,
                                GroupListResult {
                                    groups: group_infos,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(resp).await.ok();
                    }

                    rpc_methods::GROUP_LEAVE => {
                        let params: GroupLeaveParams = match deserialize_params(req.params.as_ref())
                        {
                            Ok(p) => p,
                            Err(_) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INVALID_REQUEST,
                                    "invalid params",
                                )
                                .await;
                                continue;
                            }
                        };
                        match state.inner.store.get_group(&params.group_id).await {
                            Ok(Some(_)) => {}
                            Ok(None) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::GROUP_NOT_FOUND,
                                    "group not found",
                                )
                                .await;
                                continue;
                            }
                            Err(e) => {
                                error!("get_group for {}: {e}", params.group_id);
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        }
                        match state
                            .inner
                            .store
                            .is_group_member(&params.group_id, &pub_id.0)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::NOT_A_MEMBER,
                                    "not a member of this group",
                                )
                                .await;
                                continue;
                            }
                            Err(e) => {
                                error!("is_group_member for {pub_id}: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        }
                        if let Err(e) = state
                            .inner
                            .store
                            .remove_group_member(&params.group_id, &pub_id.0)
                            .await
                        {
                            error!("remove_group_member for {pub_id}: {e}");
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INTERNAL_ERROR,
                                "internal error",
                            )
                            .await;
                            continue;
                        }
                        // Delete the group when the last member leaves.
                        let remaining = state
                            .inner
                            .store
                            .member_count(&params.group_id)
                            .await
                            .unwrap_or(1);
                        if remaining == 0 {
                            if let Err(e) = state.inner.store.delete_group(&params.group_id).await {
                                // Non-fatal: group is effectively empty; log and continue.
                                error!("delete_group (empty) {}: {e}", params.group_id);
                            }
                        }
                        // serde_json::to_string on a derived Serialize cannot fail
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, OkResult { ok: true }).unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::GROUP_SEND => {
                        let params: GroupSendParams = match deserialize_params(req.params.as_ref())
                        {
                            Ok(p) => p,
                            Err(_) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INVALID_PARAMS,
                                    "invalid params",
                                )
                                .await;
                                continue;
                            }
                        };
                        if state.inner.require_subscription
                            && !subscribed_flag.load(Ordering::Relaxed)
                        {
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::SUBSCRIPTION_REQUIRED,
                                "an active subscription is required to send messages",
                            )
                            .await;
                            continue;
                        }
                        // Verify caller is a member of the group.
                        match state
                            .inner
                            .store
                            .is_group_member(&params.group_id, &pub_id.0)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::NOT_A_MEMBER,
                                    "not a member of this group",
                                )
                                .await;
                                continue;
                            }
                            Err(e) => {
                                error!("is_group_member for {pub_id}: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        }
                        let members =
                            match state.inner.store.list_group_members(&params.group_id).await {
                                Ok(m) => m,
                                Err(e) => {
                                    error!("list_group_members for {}: {e}", params.group_id);
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INTERNAL_ERROR,
                                        "internal error",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        let message_id = Uuid::new_v4().to_string();
                        // SECURITY: `from` is always relay-set from authenticated pub_id,
                        // never taken from client params.
                        // payload is forwarded opaque — relay must never inspect it (invariant #3).
                        // serde_json::to_string on a derived Serialize cannot fail
                        let deliver_json = serde_json::to_string(
                            &JsonRpcNotification::new(
                                rpc_methods::GROUP_DELIVER,
                                GroupDeliverParams {
                                    from: pub_id.0.clone(),
                                    group_id: params.group_id,
                                    payload: params.payload,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        // Fan out to all group members except the sender.
                        state
                            .broadcast_to_group(&members, Some(&pub_id.0), deliver_json)
                            .await;
                        // serde_json::to_string on a derived Serialize cannot fail
                        let ok = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, GroupSendResult { message_id })
                                .unwrap(),
                        )
                        .unwrap();
                        client_tx.send(ok).await.ok();
                    }

                    rpc_methods::SUBSCRIBE_REQUEST => {
                        let params: SubscribeRequestParams =
                            match serde_json::from_value(req.params.unwrap_or_default()) {
                                Ok(p) => p,
                                Err(_) => {
                                    send_client_error(
                                        &client_tx,
                                        req.id,
                                        rpc_errors::INVALID_PARAMS,
                                        "invalid params",
                                    )
                                    .await;
                                    continue;
                                }
                            };
                        let merchant = match state.merchant() {
                            Some(m) => m,
                            None => {
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::METHOD_NOT_FOUND,
                                    "subscription payments not configured",
                                )
                                .await;
                                continue;
                            }
                        };
                        // Allocate a fresh Sapling payment address using the relay
                        // store's diversifier counter (the same two-step advance as
                        // alloc_fresh_address in nie-wallet, inlined here because the
                        // relay's Store is not a WalletStore).
                        let address_str = match alloc_subscription_address(
                            &merchant.dfvk,
                            &state.inner.store,
                            &merchant.network,
                        )
                        .await
                        {
                            Ok(a) => a,
                            Err(e) => {
                                error!("alloc_subscription_address failed: {e}");
                                send_client_error(
                                    &client_tx,
                                    req.id,
                                    rpc_errors::INTERNAL_ERROR,
                                    "internal error",
                                )
                                .await;
                                continue;
                            }
                        };
                        let days = params.duration_days as i64;
                        let expires_at = (chrono::Utc::now() + chrono::Duration::days(days))
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string();
                        let invoice_id = Uuid::new_v4().to_string();
                        let invoice = InvoiceRow {
                            invoice_id: invoice_id.clone(),
                            pub_id: pub_id.0.clone(),
                            address: address_str.clone(),
                            amount_zatoshi: state.inner.subscription_price_zatoshi,
                            expires_at: expires_at.clone(),
                        };
                        if let Err(e) = state.inner.store.create_invoice(&invoice).await {
                            error!("create_invoice failed: {e}");
                            send_client_error(
                                &client_tx,
                                req.id,
                                rpc_errors::INTERNAL_ERROR,
                                "internal error",
                            )
                            .await;
                            continue;
                        }
                        let result = SubscribeInvoiceResult {
                            invoice_id,
                            address: address_str,
                            amount_zatoshi: state.inner.subscription_price_zatoshi,
                            expires_at,
                        };
                        // serde_json::to_string on a derived Serialize cannot fail
                        let resp = serde_json::to_string(
                            &JsonRpcResponse::success(req.id, result).unwrap(),
                        )
                        .unwrap();
                        client_tx.send(resp).await.ok();
                    }

                    other => {
                        warn!("unknown method {other} from {pub_id}");
                        send_client_error(
                            &client_tx,
                            req.id,
                            rpc_errors::METHOD_NOT_FOUND,
                            "method not found",
                        )
                        .await;
                    }
                }
            }
            Ok(Message::Pong(_)) => {
                // Client is alive — mark pong received so the write task does
                // not time out on the next keepalive check.
                pong_received.store(true, Ordering::Relaxed);
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                error!("ws error from {pub_id}: {e}");
                break;
            }
            _ => {} // ping/binary
        }
    }

    info!("disconnected: {pub_id}");
    state.disconnect(&pub_id);

    // Tell everyone else this user has left.
    // serde_json::to_string on a derived Serialize cannot fail
    let left_json = serde_json::to_string(
        &JsonRpcNotification::new(
            rpc_methods::USER_LEFT,
            UserLeftParams {
                pub_id: pub_id.0.clone(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    state.broadcast(Some(&pub_id.0), left_json).await;

    write_task.abort();
}

/// Send a JSON-RPC error response directly on the sink (pre-auth phase only).
async fn send_error_response(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    id: u64,
    code: i32,
    message: &str,
) {
    // serde_json::to_string on a derived Serialize cannot fail
    let json = serde_json::to_string(&JsonRpcResponse::error(id, code, message)).unwrap();
    let _ = sink.send(Message::Text(json.into())).await;
}

/// Send a JSON-RPC error response via the client's channel (post-auth, main loop).
async fn send_client_error(tx: &mpsc::Sender<String>, id: u64, code: i32, message: &str) {
    // serde_json::to_string on a derived Serialize cannot fail
    let json = serde_json::to_string(&JsonRpcResponse::error(id, code, message)).unwrap();
    tx.send(json).await.ok();
}

fn deserialize_params<T: for<'de> serde::Deserialize<'de>>(
    params: Option<&serde_json::Value>,
) -> Result<T, serde_json::Error> {
    match params {
        Some(v) => serde_json::from_value(v.clone()),
        None => Err(serde::de::Error::custom("missing params")),
    }
}

/// Allocate a fresh Sapling payment address for subscription invoices.
///
/// Mirrors the two-step diversifier advance in `nie_wallet::address::alloc_fresh_address`
/// but uses the relay store's `merchant_diversifier` table instead of a `WalletStore`,
/// since the relay does not hold a full wallet database.
///
/// Returns the bech32-encoded payment address string.
async fn alloc_subscription_address(
    dfvk: &nie_wallet::address::SaplingDiversifiableFvk,
    store: &crate::store::Store,
    network: &nie_wallet::address::ZcashNetwork,
) -> anyhow::Result<String> {
    use zcash_address::{ToAddress, ZcashAddress};
    use zcash_protocol::consensus::NetworkType;

    let start: u128 = store.next_diversifier(0).await?;
    let (actual_di, addr) = dfvk.find_address(start)?;
    let actual_u128 = u128::from(actual_di);
    if actual_u128 > start {
        store.advance_diversifier_to(0, actual_u128 + 1).await?;
    }
    let network_type = match network {
        nie_wallet::address::ZcashNetwork::Mainnet => NetworkType::Main,
        nie_wallet::address::ZcashNetwork::Testnet => NetworkType::Test,
    };
    let sapling_bytes = addr.to_bytes();
    let bech32 = ZcashAddress::from_sapling(network_type, sapling_bytes).encode();
    Ok(bech32)
}
