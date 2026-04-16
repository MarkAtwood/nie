use anyhow::Result;
use nie_core::{
    identity::Identity,
    messages::ClearMessage,
    protocol::{
        rpc_methods, BroadcastParams, DeliverParams, DirectoryListParams, JsonRpcNotification,
        UserJoinedParams, UserLeftParams,
    },
    transport::{self, ClientEvent},
};

use crate::state::DaemonState;
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
    let identity = Identity::from_secret_bytes(&key_bytes);

    // Log only the public side — never log secret bytes.
    tracing::info!("loaded identity: {}", identity.pub_id());

    let conn = transport::connect_with_retry(relay_url.to_string(), identity, insecure, proxy);

    state.set_relay_tx(conn.tx).await;

    tokio::spawn(relay_event_loop(conn.rx, state, relay_url.to_string()));

    Ok(())
}

/// Background loop: receive ClientEvents from the relay connector and dispatch them.
async fn relay_event_loop(
    mut rx: tokio::sync::mpsc::Receiver<ClientEvent>,
    state: DaemonState,
    relay_url: String,
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
            }
            ClientEvent::Message(notif) => {
                dispatch_notification(notif, &state).await;
            }
            ClientEvent::Response(_) => {
                // Responses to our requests — not used in daemon v0.
                tracing::trace!("relay response received");
            }
        }
    }
}

/// Dispatch a JSON-RPC notification from the relay to daemon state and events.
async fn dispatch_notification(notif: JsonRpcNotification, state: &DaemonState) {
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
            // BROADCAST has no from field — it is a room-wide fanout.
            // In daemon v0, room messages are MLS-encrypted; we cannot decrypt them.
            tracing::debug!(
                "broadcast received ({} bytes), MLS decrypt not supported in daemon v0",
                p.payload.len()
            );
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

            let online: Vec<UserInfo> = params
                .online
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

            let offline: Vec<UserInfo> = params
                .offline
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

            state.broadcast_event(DaemonEvent::UserLeft {
                pub_id,
                display_name,
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
        let state = DaemonState::new("a".repeat(64), "test-token".to_string(), None);
        let rx = state.subscribe_events();
        (state, rx)
    }

    #[tokio::test]
    async fn test_dispatch_unknown_method() {
        let (state, mut rx) = make_test_state();
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: "unknown_method".to_string(),
            params: None,
        };
        dispatch_notification(notif, &state).await;
        // No events should be broadcast for unknown methods.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_dispatch_deliver_chat() {
        let (state, mut rx) = make_test_state();

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

        dispatch_notification(notif, &state).await;

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

        dispatch_notification(notif, &state).await;

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
        let (tx, rx_events) = tokio::sync::mpsc::channel::<ClientEvent>(8);

        tokio::spawn(relay_event_loop(
            rx_events,
            state,
            "ws://test-relay".to_string(),
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
        let (tx, rx_events) = tokio::sync::mpsc::channel::<ClientEvent>(8);

        tokio::spawn(relay_event_loop(
            rx_events,
            state,
            "ws://test-relay".to_string(),
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
        let (tx, rx_events) = tokio::sync::mpsc::channel::<ClientEvent>(8);

        let handle = tokio::spawn(relay_event_loop(
            rx_events,
            state,
            "ws://test-relay".to_string(),
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
        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::DELIVER.to_string(),
            params: None,
        };
        dispatch_notification(notif, &state).await;
        // Missing params → warn + no event.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_dispatch_directory_list() {
        let (state, mut rx) = make_test_state();

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

        dispatch_notification(notif, &state).await;

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

        dispatch_notification(notif, &state).await;

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

        dispatch_notification(notif, &state).await;

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

    /// BROADCAST path is a no-op in daemon v0 (MLS-encrypted, cannot decrypt).
    /// Regression guard: verify no DaemonEvent is broadcast for this method.
    #[tokio::test]
    async fn test_dispatch_broadcast_no_event() {
        let (state, mut rx) = make_test_state();

        let deliver = nie_core::protocol::BroadcastParams {
            payload: b"some opaque bytes".to_vec(),
        };
        let params_val = serde_json::to_value(&deliver).unwrap();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::BROADCAST.to_string(),
            params: Some(params_val),
        };

        dispatch_notification(notif, &state).await;
        assert!(
            rx.try_recv().is_err(),
            "BROADCAST must not emit DaemonEvent in daemon v0"
        );
    }

    /// SEALED_DELIVER path is a no-op in daemon v0 (requires HPKE decrypt).
    #[tokio::test]
    async fn test_dispatch_sealed_deliver_no_event() {
        let (state, mut rx) = make_test_state();

        let notif = JsonRpcNotification {
            version: "2.0".to_string(),
            method: rpc_methods::SEALED_DELIVER.to_string(),
            params: None,
        };

        dispatch_notification(notif, &state).await;
        assert!(
            rx.try_recv().is_err(),
            "SEALED_DELIVER must not emit DaemonEvent in daemon v0"
        );
    }

    /// Non-chat ClearMessage (e.g. Profile, Payment) is silently ignored in daemon v0.
    #[tokio::test]
    async fn test_dispatch_deliver_non_chat_no_event() {
        use nie_core::messages::ClearMessage;

        let (state, mut rx) = make_test_state();

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

        dispatch_notification(notif, &state).await;

        // Profile is not a ClearMessage variant — deserializes as Err → no event.
        // Even if it were a known variant, non-chat variants are silently ignored.
        assert!(
            rx.try_recv().is_err(),
            "non-chat ClearMessage must not emit DaemonEvent in daemon v0"
        );

        // Verify the test file compiles with the ClearMessage import (used only as
        // documentation of the intent — not as an oracle).
        let _ = ClearMessage::Chat {
            text: "unused".into(),
        };
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
}
