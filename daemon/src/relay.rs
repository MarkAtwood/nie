use anyhow::{Context, Result};
use nie_core::{
    identity::Identity,
    messages::ClearMessage,
    mls::MlsClient,
    protocol::{
        rpc_methods, BroadcastParams, DeliverParams, DirectoryListParams, JsonRpcNotification,
        JsonRpcRequest, PublishHpkeKeyParams, PublishKeyPackageParams, TypingNotifyParams,
        UserJoinedParams, UserLeftParams,
    },
    transport::{self, next_request_id, ClientEvent},
};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::state::DaemonState;
use crate::store::SpaceRole;
use crate::types::{DaemonEvent, UserInfo};

/// Load identity, establish a retrying relay connection, store the tx channel in
/// state, and spawn the background event dispatch loop.
pub async fn start_relay_connector(
    keyfile: &str,
    relay_url: &str,
    insecure: bool,
    proxy: Option<String>,
    state: DaemonState,
) -> Result<()> {
    let key_bytes = std::fs::read(keyfile)
        .map_err(|e| anyhow::anyhow!("failed to read keyfile {}: {}", keyfile, e))?;
    let key_bytes: [u8; 64] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("keyfile must be exactly 64 bytes"))?;
    let identity = Identity::from_secret_bytes(&key_bytes)?;

    // Log only the public side — never log secret bytes.
    tracing::info!("loaded identity: {}", identity.pub_id());

    // Extract HPKE public key before identity is moved into the transport.
    // Safe to store: this is the public half only.
    let hpke_pub_key = identity.hpke_pub_key_bytes();

    let mls_client = MlsClient::new(&identity.pub_id().0).context("create MLS client")?;
    let mls_client = Arc::new(Mutex::new(mls_client));

    // Store MLS client in state so HTTP handlers (Message/set create) can encrypt.
    state.set_mls_client(Arc::clone(&mls_client)).await;

    let conn = transport::connect_with_retry(relay_url.to_string(), identity, insecure, proxy);

    state.set_relay_tx(conn.tx).await;

    tokio::spawn(relay_event_loop(
        conn.rx,
        state,
        relay_url.to_string(),
        mls_client,
        hpke_pub_key,
    ));

    Ok(())
}

/// Background loop: receive ClientEvents from the relay connector and dispatch them.
async fn relay_event_loop(
    mut rx: tokio::sync::mpsc::Receiver<ClientEvent>,
    state: DaemonState,
    relay_url: String,
    mls: Arc<Mutex<MlsClient>>,
    hpke_pub_key: [u8; 32],
) {
    loop {
        let Some(event) = rx.recv().await else {
            // Channel closed — relay connector shut down.
            state.broadcast_event(DaemonEvent::ConnectionStateChanged {
                status: "disconnected".to_string(),
                relay_url: relay_url.clone(),
                timestamp: utc_now(),
            });
            return;
        };

        match event {
            ClientEvent::Reconnecting { delay_secs } => {
                tracing::warn!("relay disconnected, reconnecting in {}s", delay_secs);
                // Reset MLS group state — the relay loses all epoch context on disconnect.
                // Without this reset, all GROUP_DELIVER decryption fails after reconnect
                // because the daemon's stale epoch won't match the relay's fresh state.
                {
                    let mut guard = mls.lock().await;
                    match MlsClient::new(state.my_pub_id()) {
                        Ok(fresh) => {
                            *guard = fresh;
                            tracing::info!("MLS state reset for reconnect");
                        }
                        Err(e) => tracing::error!("failed to reset MLS client on reconnect: {e}"),
                    }
                }
                state.broadcast_event(DaemonEvent::ConnectionStateChanged {
                    status: "reconnecting".to_string(),
                    relay_url: relay_url.clone(),
                    timestamp: utc_now(),
                });
            }
            ClientEvent::Reconnected => {
                tracing::info!("relay reconnected");
                state.broadcast_event(DaemonEvent::ConnectionStateChanged {
                    status: "connected".to_string(),
                    relay_url: relay_url.clone(),
                    timestamp: utc_now(),
                });
                // Re-publish HPKE key and MLS key package — the relay clears these
                // slots on restart, so other clients cannot send sealed messages until
                // they are re-published.  Mirror what the CLI does on DIRECTORY_LIST.
                republish_keys(&state, &mls, hpke_pub_key).await;
            }
            ClientEvent::Message(notif) => {
                dispatch_notification(notif, &state, &mls).await;
            }
            ClientEvent::Response(_) => {
                // Responses to our requests — not used in daemon v0.
                tracing::trace!("relay response received");
            }
            ClientEvent::Disconnected => {
                tracing::warn!("relay connection closed");
                break;
            }
        }
    }
}

/// Re-publish the HPKE public key and a fresh MLS key package to the relay.
///
/// Called after every reconnect because the relay clears these slots on restart.
/// Mirrors the CLI's DIRECTORY_LIST handler.  Failures are logged as warnings —
/// the connection will reconnect again if needed, and this will be retried.
async fn republish_keys(state: &DaemonState, mls: &Arc<Mutex<MlsClient>>, hpke_pub_key: [u8; 32]) {
    let Some(tx) = state.relay_tx().await else {
        tracing::warn!("republish_keys: relay_tx not available, skipping");
        return;
    };

    // Publish a fresh MLS key package so the admin can add us to the group.
    match mls.lock().await.key_package_and_device_id() {
        Ok((kp, device_id)) => {
            match JsonRpcRequest::new(
                next_request_id(),
                rpc_methods::PUBLISH_KEY_PACKAGE,
                PublishKeyPackageParams {
                    device_id,
                    data: kp,
                },
            ) {
                Ok(req) => {
                    if tx.send(req).await.is_err() {
                        tracing::warn!("republish_keys: relay_tx closed while sending key package");
                        return;
                    }
                    tracing::info!("republished MLS key package after reconnect");
                }
                Err(e) => {
                    tracing::warn!("republish_keys: failed to build key package request: {e}")
                }
            }
        }
        Err(e) => tracing::warn!("republish_keys: key_package_and_device_id failed: {e}"),
    }

    // Publish the HPKE public key so peers can send sealed messages.
    match JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_HPKE_KEY,
        PublishHpkeKeyParams {
            public_key: hpke_pub_key.to_vec(),
        },
    ) {
        Ok(req) => {
            if tx.send(req).await.is_err() {
                tracing::warn!("republish_keys: relay_tx closed while sending HPKE key");
                return;
            }
            tracing::info!("republished HPKE key after reconnect");
        }
        Err(e) => tracing::warn!("republish_keys: failed to build HPKE key request: {e}"),
    }
}

/// Dispatch a JSON-RPC notification from the relay to daemon state and events.
async fn dispatch_notification(
    notif: JsonRpcNotification,
    state: &DaemonState,
    mls: &Arc<Mutex<MlsClient>>,
) {
    match notif.method.as_str() {
        rpc_methods::DELIVER => {
            let Some(params_val) = notif.params else {
                tracing::warn!("deliver notification missing params");
                return;
            };
            let p: DeliverParams = match serde_json::from_value(params_val) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("failed to parse deliver params: {e}");
                    return;
                }
            };
            let from = p.from;
            let payload = p.payload;

            // When MLS is active the relay should only carry encrypted BROADCAST
            // messages.  A DELIVER payload that parses as ClearMessage::Chat
            // means the sender bypassed MLS and the message arrived as plaintext.
            // Drop it so clients never silently receive unencrypted messages on
            // the pre-MLS channel while an MLS session is established.
            //
            // Release the MLS mutex before parsing: serde_json::from_slice runs
            // on relay-controlled payload and must not block other MLS operations.
            let in_group = mls.lock().await.has_group();
            if in_group
                && serde_json::from_slice::<ClearMessage>(&payload)
                    .ok()
                    .is_some_and(|m| matches!(m, ClearMessage::Chat { .. }))
            {
                tracing::warn!(
                    "deliver: dropping ClearMessage::Chat from {from} \
                     because MLS group is active (message should arrive as BROADCAST)"
                );
                return;
            }

            match serde_json::from_slice::<ClearMessage>(&payload) {
                Ok(ClearMessage::Chat { text }) => {
                    state.broadcast_event(DaemonEvent::MessageReceived {
                        from_display_name: display_name_for(&from),
                        from,
                        text,
                        timestamp: utc_now(),
                        message_id: uuid::Uuid::new_v4().to_string(),
                    });
                }
                Ok(_) => {
                    // Profile, Payment, Ack — not dispatched in daemon v0.
                    tracing::debug!("deliver: ignoring non-chat ClearMessage type");
                }
                Err(_) => {
                    // Binary (MLS-encrypted) or unknown format — not decrypted in daemon v0.
                    tracing::debug!("deliver: non-JSON payload (MLS or unknown), ignoring");
                }
            }
        }

        rpc_methods::BROADCAST => {
            let Some(params_val) = notif.params else {
                tracing::warn!("broadcast notification missing params");
                return;
            };
            let p: BroadcastParams = match serde_json::from_value(params_val) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("failed to parse broadcast params: {e}");
                    return;
                }
            };

            // Attempt MLS decryption. The sender identity is MLS-authenticated —
            // it cannot be forged by the relay or by other group members.
            let decrypt_result = mls.lock().await.process_incoming(&p.payload);
            let (plaintext, sender_pub_id) = match decrypt_result {
                Err(e) => {
                    tracing::warn!("broadcast: MLS process_incoming failed: {e}");
                    return;
                }
                Ok(None) => {
                    // Commit or proposal — group state updated internally, no message.
                    return;
                }
                Ok(Some(pair)) => pair,
            };

            match serde_json::from_slice::<ClearMessage>(&plaintext) {
                Ok(ClearMessage::Chat { text }) => {
                    dispatch_broadcast_chat(state, sender_pub_id, text).await;
                }
                Ok(ClearMessage::PeerDeliver {
                    message_id,
                    chat_id,
                    body,
                    body_type: _,
                    sent_at,
                    reply_to,
                    thread_root_id,
                }) => {
                    dispatch_peer_deliver(
                        state,
                        sender_pub_id,
                        message_id,
                        chat_id,
                        body,
                        sent_at,
                        reply_to,
                        thread_root_id,
                    )
                    .await;
                }
                Ok(ClearMessage::PeerReceipt {
                    message_id,
                    receipt_type,
                    at,
                }) => {
                    dispatch_peer_receipt(state, sender_pub_id, message_id, receipt_type, at).await;
                }
                Ok(ClearMessage::PeerTyping { chat_id, typing }) => {
                    dispatch_peer_typing(state, sender_pub_id, chat_id, typing);
                }
                Ok(ClearMessage::PeerRetract {
                    message_id,
                    for_all,
                }) => {
                    let authorized = if let Some(store) = state.store() {
                        match store.message_sender_id(&message_id).await {
                            Ok(Some(stored_sender)) => stored_sender == sender_pub_id,
                            Ok(None) => false,
                            Err(e) => {
                                tracing::warn!("peer_retract: message_sender_id failed: {e}");
                                false
                            }
                        }
                    } else {
                        tracing::warn!(
                            "peer_retract: no store configured; denying retract for message {}",
                            message_id,
                        );
                        false
                    };
                    if authorized {
                        dispatch_peer_retract(state, sender_pub_id, message_id, for_all).await;
                    } else {
                        tracing::warn!(
                            "peer_retract: sender {} does not own message {}",
                            sender_pub_id,
                            message_id,
                        );
                    }
                }
                Ok(ClearMessage::PeerGroupUpdate {
                    space_id,
                    action,
                    contact_id,
                    role,
                }) => {
                    // Only space admins may add/remove/promote/demote members.
                    // Mirror the PeerRetract pattern: check authorization before
                    // dispatching, log and drop on failure.
                    let authorized = if let Some(store) = state.store() {
                        match store.get_space_member_role(&space_id, &sender_pub_id).await {
                            Ok(Some(SpaceRole::Admin)) => true,
                            Ok(_) => false,
                            Err(e) => {
                                tracing::warn!(
                                    "peer_group_update: get_space_member_role failed: {e}"
                                );
                                false
                            }
                        }
                    } else {
                        tracing::warn!(
                            "peer_group_update: no store configured; denying group update \
                             from {} for space {}",
                            sender_pub_id,
                            space_id,
                        );
                        false
                    };
                    if authorized {
                        dispatch_peer_group_update(state, space_id, action, contact_id, role).await;
                    } else {
                        tracing::warn!(
                            "peer_group_update: sender {} is not an admin in space {}; dropping",
                            sender_pub_id,
                            space_id,
                        );
                    }
                }
                Ok(_) => {
                    tracing::debug!("broadcast: ignoring non-federated ClearMessage type");
                }
                Err(e) => {
                    tracing::warn!("broadcast: failed to deserialize ClearMessage: {e}");
                }
            };
        }

        rpc_methods::DIRECTORY_LIST => {
            let params: DirectoryListParams =
                match serde_json::from_value(notif.params.unwrap_or(serde_json::Value::Null)) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("failed to parse directory_list params: {e}");
                        return;
                    }
                };

            const MAX_DIRECTORY_ENTRIES: usize = 10_000;
            let total = params.online.len() + params.offline.len();
            let (online_src, offline_src) = if total > MAX_DIRECTORY_ENTRIES {
                tracing::warn!(
                    "directory_list: received {} entries (online={}, offline={}), \
                     truncating to {}",
                    total,
                    params.online.len(),
                    params.offline.len(),
                    MAX_DIRECTORY_ENTRIES,
                );
                let online_count = params.online.len().min(MAX_DIRECTORY_ENTRIES);
                (
                    &params.online[..online_count],
                    &params.offline[..MAX_DIRECTORY_ENTRIES.saturating_sub(online_count)],
                )
            } else {
                (&params.online[..], &params.offline[..])
            };

            let online: Vec<UserInfo> = online_src
                .iter()
                .map(|u| UserInfo {
                    pub_id: u.pub_id.clone(),
                    display_name: u
                        .nickname
                        .clone()
                        .unwrap_or_else(|| display_name_for(&u.pub_id)),
                    sequence: u.sequence,
                })
                .collect();

            let offline: Vec<UserInfo> = offline_src
                .iter()
                .map(|u| UserInfo {
                    pub_id: u.pub_id.clone(),
                    display_name: u
                        .nickname
                        .clone()
                        .unwrap_or_else(|| display_name_for(&u.pub_id)),
                    sequence: u.sequence,
                })
                .collect();

            state
                .update_directory(online.clone(), offline.clone())
                .await;

            state.broadcast_event(DaemonEvent::DirectoryUpdated {
                online,
                offline,
                timestamp: utc_now(),
            });
        }

        rpc_methods::USER_JOINED => {
            let p: UserJoinedParams =
                match serde_json::from_value(notif.params.unwrap_or(serde_json::Value::Null)) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("failed to parse user_joined params: {e}");
                        return;
                    }
                };

            let pub_id = p.pub_id;
            let sequence = p.sequence;
            let display_name = p
                .nickname
                .clone()
                .unwrap_or_else(|| display_name_for(&pub_id));

            // Update directory: insert the new user at the position that maintains
            // ascending sequence order (MLS admin election invariant).
            let mut dir = state.directory_snapshot().await;
            let pos = dir.online.partition_point(|u| u.sequence < sequence);
            dir.online.insert(
                pos,
                UserInfo {
                    pub_id: pub_id.clone(),
                    display_name: display_name.clone(),
                    sequence,
                },
            );
            state.update_directory(dir.online, dir.offline).await;

            // Auto-add to JMAP contact list and default Space membership.
            // Idempotent — safe to call on every join.
            if let Some(store) = state.store() {
                if let Err(e) = store.upsert_chat_contact(&pub_id).await {
                    tracing::warn!("user_joined: upsert_chat_contact failed: {e}");
                }
                if let Err(e) = store.set_contact_presence(&pub_id, "online").await {
                    tracing::warn!("user_joined: set_contact_presence failed: {e}");
                }
                if let Some(space_id) = state.default_space_id() {
                    if let Err(e) = store.upsert_space_member(space_id, &pub_id).await {
                        tracing::warn!("user_joined: upsert_space_member failed: {e}");
                    }
                }
            }

            state.broadcast_event(DaemonEvent::UserJoined {
                pub_id,
                display_name,
                sequence,
                timestamp: utc_now(),
            });
        }

        rpc_methods::USER_LEFT => {
            let p: UserLeftParams =
                match serde_json::from_value(notif.params.unwrap_or(serde_json::Value::Null)) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("failed to parse user_left params: {e}");
                        return;
                    }
                };

            let pub_id = p.pub_id;

            // Update directory: remove the departed user.
            let mut dir = state.directory_snapshot().await;
            let display_name = dir
                .online
                .iter()
                .find(|u| u.pub_id == pub_id)
                .map(|u| u.display_name.clone())
                .unwrap_or_else(|| display_name_for(&pub_id));
            dir.online.retain(|u| u.pub_id != pub_id);
            state.update_directory(dir.online, dir.offline).await;

            // Update presence to offline. Do NOT remove from contact list or space
            // membership — directory is persistent (design invariant).
            if let Some(store) = state.store() {
                if let Err(e) = store.set_contact_presence(&pub_id, "offline").await {
                    tracing::warn!("user_left: set_contact_presence failed: {e}");
                }
            }

            state.broadcast_event(DaemonEvent::UserLeft {
                pub_id,
                display_name,
                timestamp: utc_now(),
            });
        }

        rpc_methods::TYPING_NOTIFY => {
            let p: TypingNotifyParams =
                match serde_json::from_value(notif.params.unwrap_or(serde_json::Value::Null)) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("failed to parse typing_notify params: {e}");
                        return;
                    }
                };
            let chat_id = state.default_channel_id().unwrap_or("default").to_string();
            state.broadcast_event(DaemonEvent::Typing {
                from: p.from,
                chat_id,
                typing: p.typing,
                timestamp: utc_now(),
            });
        }

        rpc_methods::SEALED_DELIVER | rpc_methods::SEALED_BROADCAST => {
            // Sealed messages require HPKE decrypt, not implemented in daemon v0.
            tracing::debug!("received sealed message (not decrypted in daemon v0)");
        }

        rpc_methods::SEALED_WHISPER_DELIVER => {
            tracing::debug!("received sealed whisper (not decrypted in daemon v0)");
        }

        other => {
            tracing::debug!("unhandled relay method: {}", other);
        }
    }
}

async fn dispatch_broadcast_chat(state: &DaemonState, from: String, text: String) {
    state.broadcast_event(DaemonEvent::MessageReceived {
        from_display_name: display_name_for(&from),
        from,
        text,
        timestamp: utc_now(),
        message_id: uuid::Uuid::new_v4().to_string(),
    });
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_peer_deliver(
    state: &DaemonState,
    from: String,
    message_id: String,
    chat_id: String,
    body: String,
    sent_at: String,
    reply_to: Option<String>,
    thread_root_id: Option<String>,
) {
    let stored_id = if let Some(store) = state.store() {
        // Verify the chat exists before inserting; a nonexistent chat_id would
        // produce a FK violation that is silently swallowed, and then a phantom
        // MessageReceived event would still be emitted.
        match store.get_chats(Some(&[chat_id.as_str()])).await {
            Ok((_, not_found)) if !not_found.is_empty() => {
                tracing::warn!("peer_deliver: chat_id {chat_id} does not exist; dropping message");
                return;
            }
            Err(e) => {
                tracing::warn!("peer_deliver: chat lookup failed: {e}");
                return;
            }
            Ok(_) => {}
        }
        match store
            .insert_message_ext(
                &chat_id,
                &from,
                &body,
                &sent_at,
                reply_to.as_deref(),
                thread_root_id.as_deref(),
                None,
                false,
            )
            .await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("peer_deliver: insert_message_ext failed: {e}");
                message_id
            }
        }
    } else {
        message_id
    };
    state.broadcast_event(DaemonEvent::MessageReceived {
        from_display_name: display_name_for(&from),
        from,
        text: body,
        timestamp: utc_now(),
        message_id: stored_id,
    });
}

async fn dispatch_peer_receipt(
    state: &DaemonState,
    _from: String,
    message_id: String,
    receipt_type: String,
    _at: String,
) {
    // Validate receipt_type before writing: only these two values are legal for
    // peer-to-peer receipts.  "sent" is set locally by the sender and never
    // arrives over the wire; an MLS-authenticated peer can supply any string,
    // so reject anything outside the known set to prevent corruption of the
    // delivery_state column.
    let valid = matches!(receipt_type.as_str(), "delivered" | "read");
    if !valid {
        tracing::warn!(
            "peer_receipt: ignoring unknown receipt_type {:?} for message {}",
            receipt_type,
            message_id,
        );
        return;
    }
    if let Some(store) = state.store() {
        if let Err(e) = store
            .update_message_delivery_state(&message_id, &receipt_type)
            .await
        {
            tracing::warn!("peer_receipt: update_message_delivery_state failed: {e}");
        }
    }
}

fn dispatch_peer_typing(state: &DaemonState, from: String, chat_id: String, typing: bool) {
    state.broadcast_event(DaemonEvent::Typing {
        from,
        chat_id,
        typing,
        timestamp: utc_now(),
    });
}

async fn dispatch_peer_retract(
    state: &DaemonState,
    from_pub_id: String,
    message_id: String,
    for_all: bool,
) {
    // Without a store we cannot persist the retraction, so there is nothing to
    // retract from a JMAP client's perspective — emit no event.
    let Some(store) = state.store() else { return };
    if let Err(e) = store.soft_delete_message(&message_id, for_all).await {
        tracing::warn!("peer_retract: soft_delete_message failed: {e}");
        return;
    }
    state.broadcast_event(DaemonEvent::MessageRetracted {
        message_id,
        from_pub_id,
        for_all,
        timestamp: utc_now(),
    });
}

async fn dispatch_peer_group_update(
    state: &DaemonState,
    space_id: String,
    action: String,
    contact_id: String,
    role: Option<String>,
) {
    let Some(store) = state.store() else { return };
    match action.as_str() {
        "add" | "update" => {
            let parsed = role.as_deref().and_then(SpaceRole::parse);
            // Warn when the relay sends a role string we don't recognise.  The
            // coercion to Member is intentional (keeps the DB valid), but without
            // this log the mismatch is invisible — the relay's view of the member
            // role would silently differ from what we store.
            if role.is_some() && parsed.is_none() {
                tracing::warn!(
                    role = ?role,
                    space_id = %space_id,
                    contact_id = %contact_id,
                    "peer_group_update: unrecognised role from relay, defaulting to member"
                );
            }
            let role = parsed.unwrap_or(SpaceRole::Member);
            if let Err(e) = store
                .upsert_space_member_with_role(&space_id, &contact_id, role)
                .await
            {
                tracing::warn!("peer_group_update: upsert_space_member_with_role failed: {e}");
            }
        }
        "remove" => {
            if let Err(e) = store.remove_space_member(&space_id, &contact_id).await {
                tracing::warn!("peer_group_update: remove_space_member failed: {e}");
            }
        }
        other => {
            tracing::warn!("peer_group_update: unknown action '{other}'");
        }
    }
}

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Short display name derived from a pub_id: first 8 hex chars followed by ellipsis.
fn display_name_for(pub_id: &str) -> String {
    if pub_id.len() >= 8 {
        format!("{}…", &pub_id[..8])
    } else {
        pub_id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DaemonState;

    fn make_test_state() -> (DaemonState, tokio::sync::broadcast::Receiver<DaemonEvent>) {
        let state = DaemonState::new(
            "a".repeat(64),
            "test-token".to_string(),
            None,
            "mainnet".to_string(),
            None,
            None,
        );
        let rx = state.subscribe_events();
        (state, rx)
    }

    fn make_test_mls() -> Arc<Mutex<MlsClient>> {
        Arc::new(Mutex::new(
            MlsClient::new("test-pub-id").expect("MlsClient::new"),
        ))
    }

    #[tokio::test]
    async fn test_dispatch_unknown_method() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: "unknown_method".to_string(),
            params: None,
        };
        dispatch_notification(notif, &state, &mls).await;
        // No events should be broadcast for unknown methods.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_dispatch_deliver_chat() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        // Build a real ClearMessage::Chat serialized as JSON → that's the payload bytes.
        let clear = ClearMessage::Chat {
            text: "hello daemon".to_string(),
        };
        let payload_bytes = serde_json::to_vec(&clear).unwrap();

        // DeliverParams uses serde_as Base64 for payload — build via the struct.
        let deliver = nie_core::protocol::DeliverParams {
            from: "b".repeat(64),
            payload: payload_bytes,
        };
        let params_val = serde_json::to_value(&deliver).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::DELIVER.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;

        let event = rx.try_recv().expect("expected a MessageReceived event");
        match event {
            DaemonEvent::MessageReceived { from, text, .. } => {
                assert_eq!(from, "b".repeat(64));
                assert_eq!(text, "hello daemon");
            }
            other => panic!("expected MessageReceived, got {other:?}"),
        }
    }

    /// Uses a hardcoded JSON wire-format payload as an independent oracle.
    /// If ClearMessage serde representation ever changes, this test catches it.
    #[tokio::test]
    async fn test_dispatch_deliver_chat_hardcoded_payload() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        // Hardcoded JSON matching ClearMessage tag convention from CLAUDE.md:
        //   {"type":"chat","text":"..."}
        let payload_json = br#"{"type":"chat","text":"wire format test"}"#;

        let deliver = nie_core::protocol::DeliverParams {
            from: "c".repeat(64),
            payload: payload_json.to_vec(),
        };
        let params_val = serde_json::to_value(&deliver).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::DELIVER.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;

        let event = rx.try_recv().expect("expected a MessageReceived event");
        match event {
            DaemonEvent::MessageReceived { from, text, .. } => {
                assert_eq!(from, "c".repeat(64));
                assert_eq!(text, "wire format test");
            }
            other => panic!("expected MessageReceived, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_relay_event_loop_reconnected() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();
        let (tx, rx_events) = tokio::sync::mpsc::channel::<ClientEvent>(8);

        tokio::spawn(relay_event_loop(
            rx_events,
            state,
            "ws://test-relay".to_string(),
            mls,
            [0u8; 32],
        ));

        tx.send(ClientEvent::Reconnected).await.unwrap();

        // Yield to let the spawned task process the event.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let event = rx
            .try_recv()
            .expect("expected a ConnectionStateChanged event");
        match event {
            DaemonEvent::ConnectionStateChanged {
                status, relay_url, ..
            } => {
                assert_eq!(status, "connected");
                assert_eq!(relay_url, "ws://test-relay");
            }
            other => panic!("expected ConnectionStateChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_relay_event_loop_reconnecting() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();
        let (tx, rx_events) = tokio::sync::mpsc::channel::<ClientEvent>(8);

        tokio::spawn(relay_event_loop(
            rx_events,
            state,
            "ws://test-relay".to_string(),
            mls,
            [0u8; 32],
        ));

        tx.send(ClientEvent::Reconnecting { delay_secs: 5 })
            .await
            .unwrap();

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let event = rx
            .try_recv()
            .expect("expected a ConnectionStateChanged event");
        match event {
            DaemonEvent::ConnectionStateChanged { status, .. } => {
                assert_eq!(status, "reconnecting");
            }
            other => panic!("expected ConnectionStateChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_relay_event_loop_channel_closed_broadcasts_disconnected() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();
        let (tx, rx_events) = tokio::sync::mpsc::channel::<ClientEvent>(8);

        let handle = tokio::spawn(relay_event_loop(
            rx_events,
            state,
            "ws://test-relay".to_string(),
            mls,
            [0u8; 32],
        ));

        // Dropping the sender causes rx.recv() to return None → loop exits.
        drop(tx);
        handle.await.unwrap();

        let event = rx
            .try_recv()
            .expect("expected a ConnectionStateChanged event");
        match event {
            DaemonEvent::ConnectionStateChanged { status, .. } => {
                assert_eq!(status, "disconnected");
            }
            other => panic!("expected ConnectionStateChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_dispatch_deliver_missing_params() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::DELIVER.to_string(),
            params: None,
        };
        dispatch_notification(notif, &state, &mls).await;
        // Missing params → warn + no event.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_dispatch_directory_list() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        let params = nie_core::protocol::DirectoryListParams {
            online: vec![nie_core::protocol::UserInfo {
                pub_id: "c".repeat(64),
                nickname: Some("Carol".to_string()),
                sequence: 1,
            }],
            offline: vec![],
        };
        let params_val = serde_json::to_value(&params).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::DIRECTORY_LIST.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;

        let event = rx.try_recv().expect("expected a DirectoryUpdated event");
        match event {
            DaemonEvent::DirectoryUpdated {
                online, offline, ..
            } => {
                assert_eq!(online.len(), 1);
                assert_eq!(online[0].pub_id, "c".repeat(64));
                assert_eq!(online[0].display_name, "Carol");
                assert!(offline.is_empty());
            }
            other => panic!("expected DirectoryUpdated, got {other:?}"),
        }

        // Directory state should also be updated.
        let dir = state.directory_snapshot().await;
        assert_eq!(dir.online.len(), 1);
        assert_eq!(dir.online[0].pub_id, "c".repeat(64));
    }

    #[tokio::test]
    async fn test_dispatch_user_joined_sequence_order() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        // Seed directory with two users at sequences 1 and 3.
        state
            .update_directory(
                vec![
                    UserInfo {
                        pub_id: "a".repeat(64),
                        display_name: "Alice".to_string(),
                        sequence: 1,
                    },
                    UserInfo {
                        pub_id: "c".repeat(64),
                        display_name: "Carol".to_string(),
                        sequence: 3,
                    },
                ],
                vec![],
            )
            .await;

        // Drain the broadcast channel (update_directory doesn't emit events).
        let _ = rx.try_recv();

        // A user with sequence 2 joins — should be inserted between Alice and Carol.
        let params = UserJoinedParams {
            pub_id: "b".repeat(64),
            nickname: Some("Bob".to_string()),
            sequence: 2,
        };
        let params_val = serde_json::to_value(&params).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::USER_JOINED.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;

        let event = rx.try_recv().expect("expected a UserJoined event");
        match event {
            DaemonEvent::UserJoined {
                pub_id, sequence, ..
            } => {
                assert_eq!(pub_id, "b".repeat(64));
                assert_eq!(sequence, 2);
            }
            other => panic!("expected UserJoined, got {other:?}"),
        }

        // Directory order must be [Alice(1), Bob(2), Carol(3)].
        let dir = state.directory_snapshot().await;
        assert_eq!(dir.online.len(), 3);
        assert_eq!(dir.online[0].sequence, 1);
        assert_eq!(dir.online[1].sequence, 2);
        assert_eq!(dir.online[2].sequence, 3);
    }

    #[tokio::test]
    async fn test_dispatch_user_left() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        state
            .update_directory(
                vec![
                    UserInfo {
                        pub_id: "a".repeat(64),
                        display_name: "Alice".to_string(),
                        sequence: 1,
                    },
                    UserInfo {
                        pub_id: "b".repeat(64),
                        display_name: "Bob".to_string(),
                        sequence: 2,
                    },
                ],
                vec![],
            )
            .await;

        let params = UserLeftParams {
            pub_id: "a".repeat(64),
        };
        let params_val = serde_json::to_value(&params).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::USER_LEFT.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;

        let event = rx.try_recv().expect("expected a UserLeft event");
        match event {
            DaemonEvent::UserLeft { pub_id, .. } => {
                assert_eq!(pub_id, "a".repeat(64));
            }
            other => panic!("expected UserLeft, got {other:?}"),
        }

        let dir = state.directory_snapshot().await;
        assert_eq!(dir.online.len(), 1);
        assert_eq!(dir.online[0].pub_id, "b".repeat(64));
    }

    /// BROADCAST with an invalid MLS payload emits no DaemonEvent.
    /// When MLS has no active group, process_incoming returns Err → skip silently.
    /// Regression guard: verify no DaemonEvent is emitted for undecryptable payloads.
    #[tokio::test]
    async fn test_dispatch_broadcast_invalid_mls_no_event() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        let broadcast = nie_core::protocol::BroadcastParams {
            payload: b"some opaque bytes".to_vec(),
        };
        let params_val = serde_json::to_value(&broadcast).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::BROADCAST.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;
        assert!(
            rx.try_recv().is_err(),
            "BROADCAST with invalid MLS payload must not emit DaemonEvent"
        );
    }

    /// SEALED_DELIVER path is a no-op (requires HPKE decrypt, not implemented).
    #[tokio::test]
    async fn test_dispatch_sealed_deliver_no_event() {
        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::SEALED_DELIVER.to_string(),
            params: None,
        };

        dispatch_notification(notif, &state, &mls).await;
        assert!(
            rx.try_recv().is_err(),
            "SEALED_DELIVER must not emit DaemonEvent (HPKE decrypt not implemented)"
        );
    }

    /// Non-chat ClearMessage (e.g. Profile, Payment) is silently ignored.
    #[tokio::test]
    async fn test_dispatch_deliver_non_chat_no_event() {
        use nie_core::messages::ClearMessage;

        let (state, mut rx) = make_test_state();
        let mls = make_test_mls();

        // Hardcoded JSON for a non-chat variant (Profile type).
        let payload_json = br#"{"type":"profile","name":"alice"}"#;

        let deliver = nie_core::protocol::DeliverParams {
            from: "d".repeat(64),
            payload: payload_json.to_vec(),
        };
        let params_val = serde_json::to_value(&deliver).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::DELIVER.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state, &mls).await;

        // Profile is not a ClearMessage variant — deserializes as Err → no event.
        // Even if it were a known variant, non-chat variants are silently ignored.
        assert!(
            rx.try_recv().is_err(),
            "non-chat ClearMessage must not emit DaemonEvent"
        );

        // Verify the test file compiles with the ClearMessage import (used only as
        // documentation of the intent — not as an oracle).
        let _ = ClearMessage::Chat {
            text: "unused".into(),
        };
    }

    /// TYPING_NOTIFY dispatch broadcasts a DaemonEvent::Typing with the
    /// relay-provided `from` pub_id and the daemon's default channel_id.
    #[tokio::test]
    async fn test_dispatch_typing_notify() {
        let (state, mut rx) = make_test_state();
        // Seed a channel id so the dispatch can read it.
        state.set_default_channel_id("chan-01".to_string());
        let mls = make_test_mls();

        let params = nie_core::protocol::TypingNotifyParams {
            from: "d".repeat(64),
            typing: true,
        };
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::TYPING_NOTIFY.to_string(),
            params: Some(serde_json::to_value(&params).unwrap()),
        };

        dispatch_notification(notif, &state, &mls).await;

        let event = rx.try_recv().expect("expected a Typing event");
        match event {
            DaemonEvent::Typing {
                from,
                chat_id,
                typing,
                ..
            } => {
                assert_eq!(from, "d".repeat(64));
                assert_eq!(chat_id, "chan-01");
                assert!(typing);
            }
            other => panic!("expected Typing, got {other:?}"),
        }
    }

    #[test]
    fn test_display_name_for_long_pub_id() {
        let pub_id = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let name = display_name_for(pub_id);
        assert_eq!(name, "abcdef12…");
    }

    #[test]
    fn test_display_name_for_short_pub_id() {
        let name = display_name_for("abc");
        assert_eq!(name, "abc");
    }

    // ── nie-ybf3: store integration tests ────────────────────────────────

    async fn make_memory_store() -> crate::store::Store {
        crate::store::Store::new("sqlite::memory:")
            .await
            .expect("in-memory store")
    }

    fn make_state_with_store(
        store: crate::store::Store,
    ) -> (DaemonState, tokio::sync::broadcast::Receiver<DaemonEvent>) {
        let state = DaemonState::new(
            "a".repeat(64),
            "test-token".to_string(),
            None,
            "mainnet".to_string(),
            None,
            Some(store),
        );
        let rx = state.subscribe_events();
        (state, rx)
    }

    /// USER_JOINED upserts contact, sets presence online, and adds space member.
    #[tokio::test]
    async fn test_user_joined_writes_contact_and_member() {
        let store = make_memory_store().await;
        let space_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        store.create_space(space_id, "nie").await.unwrap();

        let (state, mut rx) = make_state_with_store(store);
        state.set_default_space_id(space_id.to_string());
        let mls = make_test_mls();

        let pub_id = "b".repeat(64);
        let params = UserJoinedParams {
            pub_id: pub_id.clone(),
            nickname: Some("Bob".to_string()),
            sequence: 1,
        };
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::USER_JOINED.to_string(),
            params: Some(serde_json::to_value(&params).unwrap()),
        };

        dispatch_notification(notif, &state, &mls).await;

        assert!(rx.try_recv().is_ok(), "expected UserJoined event");

        let store = state.store().unwrap();
        assert_eq!(store.contact_count().await.unwrap(), 1, "contact upserted");
        assert_eq!(
            store.space_member_count(space_id).await.unwrap(),
            1,
            "space member upserted"
        );
        assert_eq!(
            store.contact_presence(&pub_id).await.unwrap().as_deref(),
            Some("online"),
            "presence set to online"
        );
    }

    // ── Peer/* dispatch function tests ───────────────────────────────────────

    /// dispatch_broadcast_chat emits MessageReceived with the sender's pub_id.
    #[tokio::test]
    async fn test_dispatch_broadcast_chat_emits_event() {
        let (state, mut rx) = make_test_state();
        dispatch_broadcast_chat(&state, "a".repeat(64), "hello from broadcast".to_string()).await;
        let event = rx.try_recv().expect("expected MessageReceived event");
        match event {
            DaemonEvent::MessageReceived { from, text, .. } => {
                assert_eq!(from, "a".repeat(64));
                assert_eq!(text, "hello from broadcast");
            }
            other => panic!("expected MessageReceived, got {other:?}"),
        }
    }

    /// dispatch_peer_deliver stores the message and emits MessageReceived.
    #[tokio::test]
    async fn test_dispatch_peer_deliver_stores_and_emits() {
        let store = make_memory_store().await;
        let chat_id = "01JK0000000000000000000000";
        store
            .create_channel(chat_id, "general", "space-01")
            .await
            .unwrap();
        let (state, mut rx) = make_state_with_store(store);

        dispatch_peer_deliver(
            &state,
            "b".repeat(64),
            "peer-msg-id-01".to_string(),
            chat_id.to_string(),
            "peer message body".to_string(),
            "2026-04-23T10:00:00Z".to_string(),
            None,
            None,
        )
        .await;

        let event = rx.try_recv().expect("expected MessageReceived event");
        match event {
            DaemonEvent::MessageReceived { from, text, .. } => {
                assert_eq!(from, "b".repeat(64));
                assert_eq!(text, "peer message body");
            }
            other => panic!("expected MessageReceived, got {other:?}"),
        }

        let store = state.store().unwrap();
        assert_eq!(
            store.count_messages_in_chat(chat_id).await.unwrap(),
            1,
            "message inserted into store"
        );
    }

    /// dispatch_peer_receipt updates the delivery_state column.
    #[tokio::test]
    async fn test_dispatch_peer_receipt_updates_delivery_state() {
        let store = make_memory_store().await;
        let chat_id = "01JK0000000000000000000001";
        store
            .create_channel(chat_id, "general", "space-01")
            .await
            .unwrap();
        let msg_id = store
            .insert_message(chat_id, &"c".repeat(64), "body", "2026-04-23T10:00:00Z")
            .await
            .unwrap();
        let (state, _rx) = make_state_with_store(store);

        dispatch_peer_receipt(
            &state,
            "d".repeat(64),
            msg_id.clone(),
            "read".to_string(),
            "2026-04-23T10:01:00Z".to_string(),
        )
        .await;

        let store = state.store().unwrap();
        let (rows, _) = store.get_messages(&[msg_id.as_str()]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].delivery_state, "read");
    }

    /// dispatch_peer_typing emits a Typing event with the sender's pub_id and chat_id.
    #[tokio::test]
    async fn test_dispatch_peer_typing_emits_event() {
        let (state, mut rx) = make_test_state();
        dispatch_peer_typing(&state, "e".repeat(64), "chan-peer".to_string(), true);
        let event = rx.try_recv().expect("expected Typing event");
        match event {
            DaemonEvent::Typing {
                from,
                chat_id,
                typing,
                ..
            } => {
                assert_eq!(from, "e".repeat(64));
                assert_eq!(chat_id, "chan-peer");
                assert!(typing);
            }
            other => panic!("expected Typing, got {other:?}"),
        }
    }

    /// dispatch_peer_retract soft-deletes the message (excluded from count).
    #[tokio::test]
    async fn test_dispatch_peer_retract_soft_deletes() {
        let store = make_memory_store().await;
        let chat_id = "01JK0000000000000000000002";
        store
            .create_channel(chat_id, "general", "space-01")
            .await
            .unwrap();
        let msg_id = store
            .insert_message(
                chat_id,
                &"f".repeat(64),
                "retract me",
                "2026-04-23T10:00:00Z",
            )
            .await
            .unwrap();
        let (state, _rx) = make_state_with_store(store);

        dispatch_peer_retract(&state, "f".repeat(64), msg_id, true).await;

        let store = state.store().unwrap();
        assert_eq!(
            store.count_messages_in_chat(chat_id).await.unwrap(),
            0,
            "soft-deleted message excluded from count"
        );
    }

    /// dispatch_peer_group_update add action inserts space member.
    #[tokio::test]
    async fn test_dispatch_peer_group_update_add() {
        let store = make_memory_store().await;
        let space_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        store.create_space(space_id, "test").await.unwrap();
        let (state, _rx) = make_state_with_store(store);

        dispatch_peer_group_update(
            &state,
            space_id.to_string(),
            "add".to_string(),
            "g".repeat(64),
            Some("admin".to_string()),
        )
        .await;

        let store = state.store().unwrap();
        assert_eq!(
            store.space_member_count(space_id).await.unwrap(),
            1,
            "member added"
        );
    }

    /// dispatch_peer_group_update remove action deletes space member.
    #[tokio::test]
    async fn test_dispatch_peer_group_update_remove() {
        let store = make_memory_store().await;
        let space_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let contact_id = "h".repeat(64);
        store.create_space(space_id, "test").await.unwrap();
        store
            .upsert_space_member(space_id, &contact_id)
            .await
            .unwrap();
        let (state, _rx) = make_state_with_store(store);

        dispatch_peer_group_update(
            &state,
            space_id.to_string(),
            "remove".to_string(),
            contact_id,
            None,
        )
        .await;

        let store = state.store().unwrap();
        assert_eq!(
            store.space_member_count(space_id).await.unwrap(),
            0,
            "member removed"
        );
    }

    /// USER_LEFT sets presence to offline without removing the contact row.
    #[tokio::test]
    async fn test_user_left_sets_offline_keeps_contact() {
        let store = make_memory_store().await;
        let space_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        store.create_space(space_id, "nie").await.unwrap();

        let (state, mut rx) = make_state_with_store(store);
        state.set_default_space_id(space_id.to_string());
        let mls = make_test_mls();

        let pub_id = "b".repeat(64);

        // First join.
        let join_params = UserJoinedParams {
            pub_id: pub_id.clone(),
            nickname: None,
            sequence: 1,
        };
        dispatch_notification(
            JsonRpcNotification {
                version: "2.0".to_string(),
                method: rpc_methods::USER_JOINED.to_string(),
                params: Some(serde_json::to_value(&join_params).unwrap()),
            },
            &state,
            &mls,
        )
        .await;
        let _ = rx.try_recv();

        // Then leave.
        let leave_params = UserLeftParams {
            pub_id: pub_id.clone(),
        };
        dispatch_notification(
            JsonRpcNotification {
                version: "2.0".to_string(),
                method: rpc_methods::USER_LEFT.to_string(),
                params: Some(serde_json::to_value(&leave_params).unwrap()),
            },
            &state,
            &mls,
        )
        .await;
        let _ = rx.try_recv();

        let store = state.store().unwrap();
        // Contact row still present — directory is persistent.
        assert_eq!(store.contact_count().await.unwrap(), 1, "contact kept");
        // Space membership also kept.
        assert_eq!(
            store.space_member_count(space_id).await.unwrap(),
            1,
            "space member kept"
        );
        // Presence updated to offline.
        assert_eq!(
            store.contact_presence(&pub_id).await.unwrap().as_deref(),
            Some("offline"),
            "presence updated to offline"
        );
    }
}
