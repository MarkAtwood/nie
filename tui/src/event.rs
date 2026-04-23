use anyhow::Result;
use chrono::Utc;
use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use futures::StreamExt;
use nie_core::messages::ClearMessage;
use nie_core::protocol::{
    rpc_methods, BroadcastParams, DeliverParams, DirectoryListParams, JsonRpcRequest,
    KeyPackageReadyParams, PublishHpkeKeyParams, PublishKeyPackageParams, SealedDeliverParams,
    UserJoinedParams, UserLeftParams, UserNicknameParams, WhisperDeliverParams,
};
use nie_core::transport::{next_request_id, ClientEvent, RelayConnRetry};
use nie_core::{parse_zec_to_zatoshi, zatoshi_to_zec_string};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io::Stdout, time::Duration};
use tokio::time;

use crate::app::{AppState, ChatLine, ConnectionState, Focus, OnlineUser};

/// Main event loop. Runs until state.quit is set to true or the relay channel closes.
pub async fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut AppState,
    conn: RelayConnRetry,
) -> Result<()> {
    let RelayConnRetry { tx, mut rx } = conn;

    // Crossterm async event stream for keyboard/resize events
    let mut events = EventStream::new();

    // Render every 50ms even if no event (for overlay expiry, animations)
    let mut render_tick = time::interval(Duration::from_millis(50));

    // Initial draw
    terminal.draw(|f| {
        state.terminal_size = (f.area().width, f.area().height);
        crate::ui::draw(f, state);
    })?;

    loop {
        tokio::select! {
            // Relay event
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => handle_relay_event(state, &tx, event).await?,
                    None => {
                        // Channel closed — relay connection manager shut down
                        state.connection = ConnectionState::Offline;
                        state.push_message(ChatLine::System("[!] relay connection closed".to_string()));
                    }
                }
            }

            // Terminal keyboard/resize event
            maybe_term_event = events.next() => {
                match maybe_term_event {
                    Some(Ok(Event::Key(key))) => {
                        handle_key(state, &tx, key).await?;
                    }
                    Some(Ok(Event::Resize(w, h))) => {
                        state.terminal_size = (w, h);
                    }
                    Some(Err(e)) => {
                        tracing::warn!("crossterm event error: {e}");
                    }
                    _ => {}
                }
            }

            // Render tick
            _ = render_tick.tick() => {
                state.prune_overlays();
            }
        }

        // Redraw after every event
        terminal.draw(|f| {
            state.terminal_size = (f.area().width, f.area().height);
            crate::ui::draw(f, state);
        })?;

        if state.quit {
            break;
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Relay event handler
// ─────────────────────────────────────────────────────────────────

pub async fn handle_relay_event(
    state: &mut AppState,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    event: ClientEvent,
) -> Result<()> {
    match event {
        ClientEvent::Reconnecting { delay_secs } => {
            state.connection = ConnectionState::Reconnecting { delay_secs };
            state.mls_active = false;
            state.online.clear();
            state.room_hpke_secret = None;
            // Reset MLS client so the reconnected session gets a fresh OpenMLS
            // provider.  Without this, create_group() returns GroupAlreadyExists
            // on reconnect (openmls checks its storage before writing).
            let my_pub_id = state.my_pub_id.clone();
            state.mls_client = nie_core::mls::MlsClient::new(&my_pub_id).unwrap_or_else(|e| {
                tracing::warn!("failed to reset MLS client on reconnect: {e}");
                // Return the old client; it may error on create_group but that is
                // recoverable (mls_active stays false).
                nie_core::mls::MlsClient::new(&my_pub_id).unwrap()
            });
            state.push_message(ChatLine::System(format!(
                "[!] disconnected. reconnecting in {delay_secs}s…"
            )));
        }

        ClientEvent::Reconnected => {
            state.connection = ConnectionState::Connected;
            state.push_message(ChatLine::System("[!] reconnected".to_string()));
        }

        ClientEvent::Message(notif) => {
            match notif.method.as_str() {
                // ---- Directory list ----
                rpc_methods::DIRECTORY_LIST => {
                    let params: DirectoryListParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("directory_list parse error: {e}");
                            return Ok(());
                        }
                    };

                    // Rebuild nickname cache from the full directory.
                    state.nicknames.clear();
                    for u in params.online.iter().chain(params.offline.iter()) {
                        if let Some(n) = &u.nickname {
                            state.nicknames.insert(u.pub_id.clone(), n.clone());
                        }
                    }

                    // Rebuild online list — relay sends it sorted ascending by sequence.
                    state.online = params
                        .online
                        .iter()
                        .map(|u| OnlineUser {
                            pub_id: u.pub_id.clone(),
                            nickname: u.nickname.clone(),
                            sequence: u.sequence,
                        })
                        .collect();

                    state.connection = ConnectionState::Connected;

                    if !state.ever_connected {
                        state.ever_connected = true;
                        state.push_message(ChatLine::System(
                            "connected. type to chat, Ctrl-C to quit.".to_string(),
                        ));
                    }

                    // Publish key package so admin can add us.
                    if let Err(e) = publish_key_package(state, tx).await {
                        tracing::warn!("publish_key_package on DirectoryList: {e}");
                    }

                    // Publish HPKE identity key so peers can send us sealed messages.
                    if let Err(e) = publish_hpke_key(state, tx).await {
                        tracing::warn!("publish_hpke_key on DirectoryList: {e}");
                    }

                    // Admin with no group: create it now.
                    let i_am_admin = state
                        .online
                        .first()
                        .is_some_and(|u| u.pub_id == state.my_pub_id);
                    if i_am_admin && !state.mls_active {
                        match state.mls_client.create_group() {
                            Ok(()) => {
                                state.mls_active = true;
                                tracing::debug!(
                                    "MLS group created — epoch {}",
                                    state.mls_client.epoch().unwrap_or(0)
                                );
                                // Derive room HPKE keypair from MLS export_secret and
                                // publish the room public key so peers seal to the epoch key.
                                match state.mls_client.room_hpke_keypair() {
                                    Ok((room_sk, room_pk)) => {
                                        state.room_hpke_secret = Some(room_sk);
                                        // Publish room HPKE key (overwrites identity key).
                                        let req = JsonRpcRequest::new(
                                            next_request_id(),
                                            rpc_methods::PUBLISH_HPKE_KEY,
                                            PublishHpkeKeyParams {
                                                public_key: room_pk.to_vec(),
                                            },
                                        )
                                        .map_err(anyhow::Error::from)?;
                                        if tx.send(req).await.is_err() {
                                            tracing::warn!(
                                                "relay channel closed sending room HPKE key"
                                            );
                                        }
                                        tracing::debug!(
                                            "published room HPKE key for epoch {}",
                                            state.mls_client.epoch().unwrap_or(0)
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!("room_hpke_keypair after group create: {e}");
                                    }
                                }
                                state.push_message(ChatLine::System(format!(
                                    "[MLS] group created — epoch {}",
                                    state.mls_client.epoch().unwrap_or(0)
                                )));
                            }
                            Err(e) => {
                                tracing::warn!("create_group: {e}");
                            }
                        }
                    }
                }

                // ---- Peer joined ----
                rpc_methods::USER_JOINED => {
                    let p: UserJoinedParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("user_joined parse error: {e}");
                            return Ok(());
                        }
                    };

                    if let Some(n) = &p.nickname {
                        state.nicknames.insert(p.pub_id.clone(), n.clone());
                    }

                    // Insert at the position that maintains ascending sequence order.
                    // This ensures online[0] (admin) is consistent across all peers
                    // even when UserJoined events arrive in different orders.
                    let seq = p.sequence;
                    let pos = state.online.partition_point(|u| u.sequence < seq);
                    state.online.insert(
                        pos,
                        OnlineUser {
                            pub_id: p.pub_id.clone(),
                            nickname: p.nickname.clone(),
                            sequence: seq,
                        },
                    );

                    let marker = if p.pub_id == state.my_pub_id {
                        " (you)"
                    } else {
                        ""
                    };
                    state.push_message(ChatLine::System(format!(
                        "[+] {}{}",
                        state.display_name(&p.pub_id),
                        marker
                    )));

                    // Republish key package only while waiting for a Welcome.
                    // Once mls_active the admin already has our KP.
                    if !state.mls_active {
                        if let Err(e) = publish_key_package(state, tx).await {
                            tracing::warn!("publish_key_package on UserJoined: {e}");
                        }
                    }
                }

                // ---- Peer left ----
                rpc_methods::USER_LEFT => {
                    let p: UserLeftParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("user_left parse error: {e}");
                            return Ok(());
                        }
                    };

                    let name = state.display_name(&p.pub_id);
                    state.online.retain(|u| u.pub_id != p.pub_id);
                    state.push_message(ChatLine::System(format!("[-] {name} left")));
                }

                // ---- Nickname update ----
                rpc_methods::USER_NICKNAME => {
                    let p: UserNicknameParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("user_nickname parse error: {e}");
                            return Ok(());
                        }
                    };

                    let old = state.display_name(&p.pub_id);
                    state.nicknames.insert(p.pub_id.clone(), p.nickname.clone());
                    // Also update the nickname field in the online list if present.
                    for u in state.online.iter_mut() {
                        if u.pub_id == p.pub_id {
                            u.nickname = Some(p.nickname.clone());
                            break;
                        }
                    }
                    let marker = if p.pub_id == state.my_pub_id {
                        " (you)"
                    } else {
                        ""
                    };
                    state.push_message(ChatLine::System(format!(
                        "[~] {old} is now known as \"{}\"{marker}",
                        p.nickname
                    )));
                }

                // ---- Incoming room message ----
                rpc_methods::DELIVER => {
                    let p: DeliverParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("deliver parse error: {e}");
                            return Ok(());
                        }
                    };
                    decrypt_and_display(state, &p.from, &p.payload).await?;
                }

                // ---- Sealed broadcast received ----
                rpc_methods::SEALED_DELIVER => {
                    let p: SealedDeliverParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("sealed_deliver parse error: {e}");
                            return Ok(());
                        }
                    };

                    // Choose HPKE key: room key if MLS active and derived, else identity key.
                    let plaintext = {
                        let active_secret: &[u8; 32] = if state.mls_active {
                            match state.room_hpke_secret.as_ref() {
                                Some(sk) => sk,
                                None => {
                                    tracing::warn!(
                                        "sealed_deliver while mls_active but no room_hpke_secret"
                                    );
                                    return Ok(());
                                }
                            }
                        } else {
                            &state.hpke_identity_secret
                        };
                        match nie_core::hpke::unseal_message(active_secret, &p.sealed) {
                            Ok(pt) => pt,
                            Err(e) => {
                                tracing::warn!("sealed_deliver unseal failed: {e}");
                                return Ok(());
                            }
                        }
                    };

                    // Sealed plaintext is just the MLS ciphertext — no prefix.
                    // Sender identity is authenticated by MLS (process_incoming
                    // returns the credential bytes) rather than the old self-asserted
                    // 64-byte prefix that HPKE base mode cannot authenticate.
                    if !state.mls_active {
                        // Drop sealed messages that arrive before our Welcome.
                        return Ok(());
                    }

                    decrypt_and_display(state, "", &plaintext).await?;
                }

                // ---- Whisper: DM or MLS Welcome ----
                rpc_methods::WHISPER_DELIVER => {
                    let p: WhisperDeliverParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("whisper_deliver parse error: {e}");
                            return Ok(());
                        }
                    };

                    match serde_json::from_slice::<ClearMessage>(&p.payload) {
                        Ok(ClearMessage::Chat { text }) => {
                            let from_name = state.display_name(&p.from);
                            state.push_message(ChatLine::Chat {
                                from: format!("DM:{from_name}"),
                                text,
                                ts: Utc::now(),
                            });
                        }
                        Ok(_) => {
                            tracing::warn!(
                                "unexpected ClearMessage type in WhisperDeliver from {}",
                                p.from
                            );
                        }
                        Err(_) => {
                            // Binary payload → treat as MLS Welcome.
                            if !state.mls_active {
                                match state.mls_client.join_from_welcome(&p.payload) {
                                    Ok(()) => {
                                        state.mls_active = true;
                                        tracing::debug!(
                                            "MLS joined group — epoch {}",
                                            state.mls_client.epoch().unwrap_or(0)
                                        );
                                        // Derive and publish room HPKE key.
                                        match state.mls_client.room_hpke_keypair() {
                                            Ok((room_sk, room_pk)) => {
                                                state.room_hpke_secret = Some(room_sk);
                                                let req = JsonRpcRequest::new(
                                                    next_request_id(),
                                                    rpc_methods::PUBLISH_HPKE_KEY,
                                                    PublishHpkeKeyParams {
                                                        public_key: room_pk.to_vec(),
                                                    },
                                                )
                                                .map_err(anyhow::Error::from)?;
                                                if tx.send(req).await.is_err() {
                                                    tracing::warn!(
                                                        "relay channel closed sending room HPKE key"
                                                    );
                                                }
                                                tracing::debug!(
                                                    "published room HPKE key for epoch {}",
                                                    state.mls_client.epoch().unwrap_or(0)
                                                );
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "room_hpke_keypair after Welcome: {e}"
                                                );
                                            }
                                        }
                                        state.push_message(ChatLine::System(format!(
                                            "[MLS] joined group — epoch {}",
                                            state.mls_client.epoch().unwrap_or(0)
                                        )));
                                    }
                                    Err(e) => {
                                        tracing::warn!("join_from_welcome: {e}");
                                    }
                                }
                            }
                        }
                    }
                }

                // ---- Key package ready — admin fetches to add the new member ----
                // Full add-member flow (GetKeyPackage → Response → add_member + broadcast)
                // requires request-response correlation and is deferred to a future issue.
                // Here we issue the GetKeyPackage request; the Response handler is a stub.
                rpc_methods::KEY_PACKAGE_READY => {
                    let p: KeyPackageReadyParams = match serde_json::from_value(
                        notif.params.unwrap_or(serde_json::Value::Null),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("key_package_ready parse error: {e}");
                            return Ok(());
                        }
                    };

                    let ready_id = p.pub_id;
                    let ready_device_id = p.device_id;
                    let i_am_admin = state
                        .online
                        .first()
                        .is_some_and(|u| u.pub_id == state.my_pub_id);

                    if i_am_admin && state.mls_active && ready_id != state.my_pub_id {
                        let kp_params = if !state.mls_client.group_contains(&ready_id) {
                            // New user: fetch all devices.
                            nie_core::protocol::GetKeyPackageParams {
                                pub_id: ready_id.clone(),
                                device_id: None,
                            }
                        } else {
                            // Existing group member: fetch only this new device.
                            nie_core::protocol::GetKeyPackageParams {
                                pub_id: ready_id.clone(),
                                device_id: Some(ready_device_id),
                            }
                        };
                        let req = JsonRpcRequest::new(
                            next_request_id(),
                            rpc_methods::GET_KEY_PACKAGE,
                            kp_params,
                        )
                        .map_err(anyhow::Error::from)?;
                        if tx.send(req).await.is_err() {
                            tracing::warn!("relay channel closed sending GetKeyPackage");
                        }
                        tracing::debug!("admin: GetKeyPackage sent for {ready_id}");
                    }
                }

                other => {
                    tracing::debug!("relay notification (unhandled): {other}");
                }
            }
        }

        ClientEvent::Response(resp) => {
            // Stub — add-member response correlation is a future issue.
            tracing::debug!("relay response id={}", resp.id);
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Helper: publish own MLS key package
// ─────────────────────────────────────────────────────────────────

async fn publish_key_package(
    state: &mut AppState,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
) -> Result<()> {
    let (kp, device_id) = state.mls_client.key_package_and_device_id()?;
    tracing::debug!("publishing key package ({} bytes)", kp.len());
    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_KEY_PACKAGE,
        PublishKeyPackageParams {
            device_id,
            data: kp,
        },
    )
    .map_err(anyhow::Error::from)?;
    if tx.send(req).await.is_err() {
        tracing::warn!("relay channel closed while publishing key package");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Helper: publish own HPKE identity public key
// ─────────────────────────────────────────────────────────────────

async fn publish_hpke_key(
    state: &mut AppState,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
) -> Result<()> {
    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::PUBLISH_HPKE_KEY,
        PublishHpkeKeyParams {
            public_key: state.hpke_identity_pub.to_vec(),
        },
    )
    .map_err(anyhow::Error::from)?;
    if tx.send(req).await.is_err() {
        tracing::warn!("relay channel closed while publishing HPKE key");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Payment state-machine transition guard
// ─────────────────────────────────────────────────────────────────

/// Returns true when `action` is a legal next step from `current` for `role`.
///
/// Valid transitions:
/// - Payer in Requested   → receives Address  (payee is providing the address)
/// - Payee in Requested   → receives Sent     (payer has broadcast the tx)
/// - Payer in AddressProvided → receives Confirmed (payee confirmed receipt)
/// - Either role in any non-terminal state → receives Cancelled
///
/// `Unknown` is always accepted (error response, no state mutation).
/// `Request` is not guarded here — the payer creates the session locally;
/// receiving a Request from a peer creates a new payee session, so there
/// is no prior state to validate against.
fn is_valid_transition(
    current: &nie_core::messages::PaymentState,
    action: &nie_core::messages::PaymentAction,
    role: &nie_core::messages::PaymentRole,
) -> bool {
    use nie_core::messages::{PaymentAction, PaymentRole, PaymentState};

    // Terminal states accept no further transitions.
    let is_terminal = matches!(
        current,
        PaymentState::Confirmed | PaymentState::Failed | PaymentState::Expired
    );
    if is_terminal {
        return matches!(action, PaymentAction::Unknown { .. });
    }

    match action {
        // Payer sent Request; payee responds with their address.
        // The payer's session is in Requested waiting for this.
        PaymentAction::Address { .. } => {
            matches!(role, PaymentRole::Payer) && matches!(current, PaymentState::Requested)
        }
        // Payer broadcast the tx and sent Sent.
        // The payee's session is in Requested waiting for this.
        PaymentAction::Sent { .. } => {
            matches!(role, PaymentRole::Payee) && matches!(current, PaymentState::Requested)
        }
        // Payee confirmed on-chain receipt.
        // The payer's session is in AddressProvided waiting for this.
        PaymentAction::Confirmed { .. } => {
            matches!(role, PaymentRole::Payer) && matches!(current, PaymentState::AddressProvided)
        }
        // Either party may cancel at any non-terminal state (terminal guard is above).
        PaymentAction::Cancelled { .. } => true,
        // Unknown is an error reply; always display, never mutate state.
        PaymentAction::Unknown { .. } => true,
        // Request creates a new session; no prior state to guard.
        PaymentAction::Request { .. } => true,
    }
}

// ─────────────────────────────────────────────────────────────────
// Helper: decrypt payload and push to message log
// ─────────────────────────────────────────────────────────────────

async fn decrypt_and_display(
    state: &mut AppState,
    from_pub_id: &str,
    payload: &[u8],
) -> Result<()> {
    // When MLS is active, use the MLS-authenticated sender (returned by
    // process_incoming). This prevents forged from-prefixes in sealed messages
    // — HPKE base mode provides no sender auth, but MLS does.
    let (plaintext, effective_from): (Vec<u8>, String) = if state.mls_active {
        match state.mls_client.process_incoming(payload) {
            Ok(Some((pt, mls_sender))) => (pt, mls_sender),
            Ok(None) => {
                // MLS Commit — group state updated, advance epoch.
                tracing::debug!(
                    "MLS commit applied — epoch {}",
                    state.mls_client.epoch().unwrap_or(0)
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("MLS process_incoming: {e}");
                return Ok(());
            }
        }
    } else {
        (payload.to_vec(), from_pub_id.to_string())
    };

    match serde_json::from_slice::<ClearMessage>(&plaintext) {
        Ok(ClearMessage::Chat { text }) => {
            state.push_message(ChatLine::Chat {
                from: effective_from.clone(),
                text,
                ts: Utc::now(),
            });
        }
        Ok(ClearMessage::Profile { fields }) => {
            if let Some(name) = fields.get("name") {
                state.nicknames.insert(effective_from.clone(), name.clone());
            }
        }
        Ok(ClearMessage::Payment { session_id, action }) => {
            use nie_core::messages::{PaymentAction, PaymentState};
            let from_name = state.display_name(&effective_from).to_string();
            let overlay_text = match &action {
                PaymentAction::Request {
                    chain,
                    amount_zatoshi,
                } => {
                    // Receiving a Request from a peer creates a new payee session.
                    let now = chrono::Utc::now().timestamp();
                    let session = nie_core::messages::PaymentSession {
                        id: session_id,
                        chain: *chain,
                        amount_zatoshi: *amount_zatoshi,
                        peer_pub_id: effective_from.clone(),
                        role: nie_core::messages::PaymentRole::Payee,
                        state: nie_core::messages::PaymentState::Requested,
                        created_at: now,
                        updated_at: now,
                        tx_hash: None,
                        address: None,
                    };
                    state.sessions.entry(session_id).or_insert_with(|| session);
                    format!(
                        "Payment request from {from_name}: {} ZEC",
                        zatoshi_to_zec_string(*amount_zatoshi)
                    )
                }
                PaymentAction::Address { address, .. } => {
                    // Update the session with the provided address if we are the payer.
                    if let Some(sess) = state.sessions.get_mut(&session_id) {
                        if is_valid_transition(&sess.state, &action, &sess.role) {
                            sess.address = Some(address.clone());
                            sess.state = PaymentState::AddressProvided;
                            sess.updated_at = chrono::Utc::now().timestamp();
                        } else {
                            tracing::warn!(
                                "payment session {}: ignoring Address in state {:?} as {:?}",
                                session_id,
                                sess.state,
                                sess.role,
                            );
                        }
                    }
                    format!("Payment address received from {from_name}")
                }
                PaymentAction::Sent {
                    tx_hash,
                    amount_zatoshi,
                    ..
                } => {
                    if let Some(sess) = state.sessions.get_mut(&session_id) {
                        if !is_valid_transition(&sess.state, &action, &sess.role) {
                            tracing::warn!(
                                "payment session {}: ignoring Sent in state {:?} as {:?}",
                                session_id,
                                sess.state,
                                sess.role,
                            );
                            return Ok(());
                        }
                        sess.state = PaymentState::Sent;
                        sess.updated_at = chrono::Utc::now().timestamp();
                    }
                    let short_hash: String = tx_hash.chars().take(16).collect();
                    format!(
                        "Payment sent by {from_name}: {} ZEC (tx {})",
                        zatoshi_to_zec_string(*amount_zatoshi),
                        short_hash
                    )
                }
                PaymentAction::Confirmed { tx_hash } => {
                    if let Some(sess) = state.sessions.get_mut(&session_id) {
                        if is_valid_transition(&sess.state, &action, &sess.role) {
                            sess.state = PaymentState::Confirmed;
                            sess.tx_hash = Some(tx_hash.clone());
                            sess.updated_at = chrono::Utc::now().timestamp();
                        } else {
                            tracing::warn!(
                                "payment session {}: ignoring Confirmed in state {:?} as {:?}",
                                session_id,
                                sess.state,
                                sess.role,
                            );
                        }
                    }
                    format!("Payment confirmed! (from {from_name})")
                }
                PaymentAction::Cancelled { reason } => {
                    if let Some(sess) = state.sessions.get_mut(&session_id) {
                        if is_valid_transition(&sess.state, &action, &sess.role) {
                            sess.state = PaymentState::Expired;
                            sess.updated_at = chrono::Utc::now().timestamp();
                        } else {
                            tracing::warn!(
                                "payment session {}: ignoring Cancelled in state {:?} as {:?}",
                                session_id,
                                sess.state,
                                sess.role,
                            );
                        }
                    }
                    format!("Payment cancelled by {from_name}: {reason}")
                }
                PaymentAction::Unknown { reason } => {
                    format!("Unknown payment action from {from_name}: {reason}")
                }
            };
            state.push_overlay(overlay_text);
        }
        Ok(ClearMessage::Ack { .. }) => {
            // Acks are informational only; no display needed.
        }
        Ok(ClearMessage::FileHeader { .. }) | Ok(ClearMessage::FileChunk { .. }) => {
            // File transfer not yet supported in TUI.
            tracing::warn!("received file transfer message — not yet supported in TUI, ignoring");
        }
        Err(_) => {
            state.push_message(ChatLine::System("[!] unreadable message".to_string()));
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Keyboard handler (stub — full implementation in W2B)
// ─────────────────────────────────────────────────────────────────

async fn handle_key(
    state: &mut AppState,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    key: crossterm::event::KeyEvent,
) -> Result<()> {
    match key.code {
        // Quit
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.quit = true;
        }
        KeyCode::Char('q') if state.focus == Focus::UserList => {
            state.quit = true;
        }

        // Scroll
        KeyCode::PageUp => {
            let page = state.terminal_size.1.saturating_sub(6) as usize;
            state.scroll_offset = state.scroll_offset.saturating_add(page);
            state.clamp_scroll();
        }
        KeyCode::PageDown => {
            let page = state.terminal_size.1.saturating_sub(6) as usize;
            state.scroll_offset = state.scroll_offset.saturating_sub(page);
            state.clamp_scroll();
        }
        KeyCode::Esc => {
            state.scroll_offset = 0; // jump to bottom
        }

        // Tab: cycle focus
        KeyCode::Tab => {
            state.focus = match state.focus {
                Focus::Input => Focus::UserList,
                Focus::UserList => Focus::Input,
            };
        }

        // Text input
        KeyCode::Enter => {
            let line = state.input.trim().to_string();
            if !line.is_empty() {
                state.input.clear();
                state.input_cursor = 0;
                state.scroll_offset = 0;
                if line.starts_with('/') {
                    handle_slash(state, tx, &line).await?;
                } else {
                    send_chat(state, tx, &line).await?;
                }
            }
        }
        KeyCode::Char(c)
            if key.modifiers == KeyModifiers::NONE || key.modifiers == KeyModifiers::SHIFT =>
        {
            if state.input.len() < 65536 {
                state.input.insert(state.input_cursor, c);
                state.input_cursor += c.len_utf8();
            }
        }
        KeyCode::Backspace => {
            if state.input_cursor > 0 {
                // Find previous char boundary
                let mut pos = state.input_cursor - 1;
                while !state.input.is_char_boundary(pos) {
                    pos -= 1;
                }
                state.input.remove(pos);
                state.input_cursor = pos;
            }
        }
        KeyCode::Delete => {
            if state.input_cursor < state.input.len() {
                if let Some((_, ch)) = state.input[state.input_cursor..].char_indices().next() {
                    state
                        .input
                        .drain(state.input_cursor..state.input_cursor + ch.len_utf8());
                }
            }
        }
        KeyCode::Left => {
            if state.input_cursor > 0 {
                let mut pos = state.input_cursor - 1;
                while !state.input.is_char_boundary(pos) {
                    pos -= 1;
                }
                state.input_cursor = pos;
            }
        }
        KeyCode::Right => {
            if state.input_cursor < state.input.len() {
                let mut pos = state.input_cursor + 1;
                while pos <= state.input.len() && !state.input.is_char_boundary(pos) {
                    pos += 1;
                }
                state.input_cursor = pos;
            }
        }
        KeyCode::Home => {
            state.input_cursor = 0;
        }
        KeyCode::End => {
            state.input_cursor = state.input.len();
        }
        _ => {}
    }
    Ok(())
}

async fn send_chat(
    state: &mut AppState,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    text: &str,
) -> Result<()> {
    // Build plaintext payload (MLS encryption will be added when mls_active)
    let payload = serde_json::to_vec(&ClearMessage::Chat {
        text: text.to_string(),
    })
    .expect("ClearMessage::Chat serialization cannot fail");

    let params = BroadcastParams { payload };
    let req = JsonRpcRequest::new(next_request_id(), rpc_methods::BROADCAST, &params)
        .map_err(anyhow::Error::from)?;

    if tx.send(req).await.is_err() {
        tracing::warn!("relay send channel closed while sending chat");
    }

    // Append own message to local chat log
    state.push_message(crate::app::ChatLine::Chat {
        from: state.my_pub_id.clone(),
        text: text.to_string(),
        ts: chrono::Utc::now(),
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Payment amount helpers
// ─────────────────────────────────────────────────────────────────

async fn handle_slash(
    state: &mut AppState,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    line: &str,
) -> Result<()> {
    // Split: /cmd [rest]
    let (cmd, rest) = line[1..].split_once(' ').unwrap_or((&line[1..], ""));
    let cmd = cmd.to_lowercase();

    match cmd.as_str() {
        "quit" | "q" => {
            state.quit = true;
        }
        "help" | "h" => {
            state.push_message(ChatLine::System(
                "Commands: /quit /who /iam <nick> /me <action> /alias <name> <pubid> /dm <handle> <msg> /! <cmd> /cat <path> /set <k> <v> /unset <k> /profile /balance /receive /pay <handle> <amount> /payments /clear /help".to_string(),
            ));
        }
        "clear" => {
            state.messages.clear();
            state.scroll_offset = 0;
        }
        "who" => {
            let names: Vec<String> = state
                .online
                .iter()
                .enumerate()
                .map(|(i, u)| {
                    let marker = if i == 0 { "[A] " } else { "    " };
                    format!("{marker}{}", state.display_name(&u.pub_id))
                })
                .collect();
            for name in names {
                state.push_message(ChatLine::System(name));
            }
        }
        "iam" if !rest.is_empty() => {
            let nick = rest.trim().to_string();
            if nick.len() > 64 {
                state.push_message(ChatLine::System(
                    "Nickname too long (max 64 chars)".to_string(),
                ));
                return Ok(());
            }
            use nie_core::protocol::SetNicknameParams;
            let params = SetNicknameParams {
                nickname: nick.clone(),
            };
            let req = JsonRpcRequest::new(next_request_id(), rpc_methods::SET_NICKNAME, &params)
                .map_err(anyhow::Error::from)?;
            if tx.send(req).await.is_err() {
                tracing::warn!("relay channel closed during /iam");
            }
            state.own_profile.insert("name".to_string(), nick.clone());
            state.nicknames.insert(state.my_pub_id.clone(), nick);
        }
        "iam" => {
            state.push_message(ChatLine::System("Usage: /iam <nickname>".to_string()));
        }
        "me" if !rest.is_empty() => {
            let action_text = format!("\x01ACTION {rest}\x01");
            send_chat(state, tx, &action_text).await?;
        }
        "me" => {
            state.push_message(ChatLine::System("Usage: /me <action>".to_string()));
        }
        "alias" => {
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().to_string();
                let pubkey = parts[1].trim().to_string();
                state.local_names.insert(pubkey.clone(), name.clone());
                state.push_message(ChatLine::System(format!("Alias set: {name} → {pubkey}")));
            } else {
                state.push_message(ChatLine::System(
                    "Usage: /alias <name> <pubkey>".to_string(),
                ));
            }
        }
        "dm" => {
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let handle = parts[0].trim();
                let msg_text = parts[1].trim();
                let to_pub_id = state
                    .online
                    .iter()
                    .find(|u| {
                        state.display_name(&u.pub_id).eq_ignore_ascii_case(handle)
                            || u.pub_id.starts_with(handle)
                    })
                    .map(|u| u.pub_id.clone())
                    .or_else(|| {
                        state
                            .local_names
                            .iter()
                            .find(|(_, name)| name.eq_ignore_ascii_case(handle))
                            .map(|(k, _)| k.clone())
                    });
                if let Some(to_id) = to_pub_id {
                    use nie_core::protocol::WhisperParams;
                    let payload = serde_json::to_vec(&ClearMessage::Chat {
                        text: msg_text.to_string(),
                    })
                    // serde_json::to_vec on a derived Serialize cannot fail
                    .expect("ClearMessage serialization cannot fail");
                    let params = WhisperParams { to: to_id, payload };
                    let req = JsonRpcRequest::new(next_request_id(), rpc_methods::WHISPER, &params)
                        .map_err(anyhow::Error::from)?;
                    if tx.send(req).await.is_err() {
                        tracing::warn!("relay channel closed during /dm");
                    }
                    state.push_message(ChatLine::System(format!("→ {handle}: {msg_text}")));
                } else {
                    state.push_message(ChatLine::System(format!("Unknown user: {handle}")));
                }
            } else {
                state.push_message(ChatLine::System(
                    "Usage: /dm <handle> <message>".to_string(),
                ));
            }
        }
        "!" if !rest.is_empty() => {
            // SECURITY: shlex split prevents shell injection — do NOT change to sh -c
            match shlex::split(rest) {
                Some(argv) if !argv.is_empty() => {
                    match std::process::Command::new(&argv[0])
                        .args(&argv[1..])
                        .output()
                    {
                        Ok(output) => {
                            let raw = String::from_utf8_lossy(&output.stdout);
                            let truncated: &str = if raw.len() > 4096 {
                                // Find the last char boundary at or before byte 4096
                                let end = raw
                                    .char_indices()
                                    .map(|(i, _)| i)
                                    .take_while(|&i| i <= 4096)
                                    .last()
                                    .unwrap_or(0);
                                &raw[..end]
                            } else {
                                &raw
                            };
                            let safe = crate::ui::strip_unsafe(truncated);
                            if !safe.trim().is_empty() {
                                send_chat(state, tx, &safe).await?;
                            }
                        }
                        Err(e) => {
                            state.push_message(ChatLine::System(format!("[!] command error: {e}")));
                        }
                    }
                }
                _ => {
                    state.push_message(ChatLine::System("Invalid command syntax".to_string()));
                }
            }
        }
        "!" => {
            state.push_message(ChatLine::System(
                "Usage: /! <command> [args...]".to_string(),
            ));
        }
        "cat" if !rest.is_empty() => {
            let path = std::path::Path::new(rest.trim());
            match std::fs::read(path) {
                Ok(bytes) => {
                    let truncated = if bytes.len() > 4096 {
                        &bytes[..4096]
                    } else {
                        &bytes
                    };
                    let content = String::from_utf8_lossy(truncated).to_string();
                    let safe = crate::ui::strip_unsafe(&content);
                    if !safe.trim().is_empty() {
                        send_chat(state, tx, &safe).await?;
                    }
                }
                Err(e) => {
                    state.push_message(ChatLine::System(format!("[!] cannot read file: {e}")));
                }
            }
        }
        "cat" => {
            state.push_message(ChatLine::System("Usage: /cat <path>".to_string()));
        }
        "set" => {
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() == 2 {
                state
                    .own_profile
                    .insert(parts[0].trim().to_string(), parts[1].trim().to_string());
                state.push_message(ChatLine::System(format!(
                    "Profile: {} = {}",
                    parts[0].trim(),
                    parts[1].trim()
                )));
            } else {
                state.push_message(ChatLine::System("Usage: /set <key> <value>".to_string()));
            }
        }
        "unset" if !rest.is_empty() => {
            let key = rest.trim();
            if state.own_profile.remove(key).is_some() {
                state.push_message(ChatLine::System(format!("Profile: {key} removed")));
            } else {
                state.push_message(ChatLine::System(format!("Profile: no field '{key}'")));
            }
        }
        "unset" => {
            state.push_message(ChatLine::System("Usage: /unset <key>".to_string()));
        }
        "profile" => {
            if !rest.trim().is_empty() {
                state.push_message(ChatLine::System(
                    "Peer profile lookup not yet implemented.".to_string(),
                ));
                return Ok(());
            }
            if state.own_profile.is_empty() {
                state.push_message(ChatLine::System("(no profile fields set)".to_string()));
            } else {
                let lines: Vec<String> = state
                    .own_profile
                    .iter()
                    .map(|(k, v)| format!("  {k}: {v}"))
                    .collect();
                for line in lines {
                    state.push_message(ChatLine::System(line));
                }
            }
        }
        "balance" => {
            let wallet = state.wallet.as_ref().map(std::sync::Arc::clone);
            if let Some(ws) = wallet {
                match ws.scan_tip().await {
                    Ok(tip) => match ws.balance(tip, 10).await {
                        Ok(bal) => {
                            state.push_message(ChatLine::System(format!(
                                "Balance: {} ZEC confirmed, {} ZEC pending",
                                zatoshi_to_zec_string(bal.confirmed_zatoshi),
                                zatoshi_to_zec_string(bal.pending_zatoshi),
                            )));
                        }
                        Err(e) => {
                            state.push_message(ChatLine::System(format!("[!] balance error: {e}")));
                        }
                    },
                    Err(e) => {
                        state.push_message(ChatLine::System(format!("[!] scan_tip error: {e}")));
                    }
                }
            } else {
                state.push_message(ChatLine::System(
                    "Wallet not initialized. Run: nie wallet init".to_string(),
                ));
            }
        }

        "receive" => {
            let wallet = state.wallet.as_ref().map(std::sync::Arc::clone);
            if let Some(ws) = wallet {
                match ws.get_diversifier_index(0).await {
                    Ok(idx) => {
                        state.push_message(ChatLine::System(format!(
                            "Diversifier index: {idx}. Use `nie wallet` for full address generation."
                        )));
                    }
                    Err(e) => {
                        state.push_message(ChatLine::System(format!("[!] receive error: {e}")));
                    }
                }
            } else {
                state.push_message(ChatLine::System(
                    "Wallet not initialized. Run: nie wallet init".to_string(),
                ));
            }
        }

        "pay" => {
            // /pay <handle> <amount> [chain]
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                state.push_message(ChatLine::System(
                    "Usage: /pay <handle> <amount> [zcash]".to_string(),
                ));
                return Ok(());
            }
            let handle = parts[0].trim();
            let amount_str = parts[1].trim();
            let chain = if parts.len() > 2 {
                match parts[2].trim().to_lowercase().as_str() {
                    "zcash" | "zec" => nie_core::messages::Chain::Zcash,
                    other => {
                        state.push_message(ChatLine::System(format!(
                            "Unknown chain: {other}. Use: zcash"
                        )));
                        return Ok(());
                    }
                }
            } else {
                nie_core::messages::Chain::Zcash
            };

            let amount_zatoshi = match parse_zec_to_zatoshi(amount_str) {
                Ok(z) if z < 1000 => {
                    state.push_message(ChatLine::System(
                        "Amount too small (min 0.00001 ZEC)".to_string(),
                    ));
                    return Ok(());
                }
                Ok(z) => z,
                Err(e) => {
                    state.push_message(ChatLine::System(format!("[!] Invalid amount: {e}")));
                    return Ok(());
                }
            };

            let to_pub_id = state
                .online
                .iter()
                .find(|u| {
                    state.display_name(&u.pub_id).eq_ignore_ascii_case(handle)
                        || u.pub_id.starts_with(handle)
                })
                .map(|u| u.pub_id.clone());

            let peer_pub_id = match to_pub_id {
                Some(id) => id,
                None => {
                    state.push_message(ChatLine::System(format!("Unknown user: {handle}")));
                    return Ok(());
                }
            };

            use nie_core::messages::{PaymentRole, PaymentState};
            let now = chrono::Utc::now().timestamp();
            let session = nie_core::messages::PaymentSession {
                id: uuid::Uuid::new_v4(),
                chain,
                amount_zatoshi,
                peer_pub_id: peer_pub_id.clone(),
                role: PaymentRole::Payer,
                state: PaymentState::Requested,
                created_at: now,
                updated_at: now,
                tx_hash: None,
                address: None,
            };

            // Persist to wallet if available (best-effort — failure is logged, not fatal).
            let wallet = state.wallet.as_ref().map(std::sync::Arc::clone);
            if let Some(ws) = wallet {
                if let Err(e) = ws.upsert_session(&session).await {
                    tracing::warn!("failed to persist payment session: {e}");
                }
            }

            state.sessions.insert(session.id, session.clone());

            use nie_core::messages::{ClearMessage, PaymentAction};
            let action = PaymentAction::Request {
                chain,
                amount_zatoshi,
            };
            let payload = serde_json::to_vec(&ClearMessage::Payment {
                session_id: session.id,
                action,
            })
            // serde_json::to_vec on a derived Serialize cannot fail
            .expect("ClearMessage serialization cannot fail");
            let params = BroadcastParams { payload };
            let req = JsonRpcRequest::new(next_request_id(), rpc_methods::BROADCAST, &params)
                .map_err(anyhow::Error::from)?;
            if tx.send(req).await.is_err() {
                tracing::warn!("relay channel closed during /pay");
            }

            state.push_message(ChatLine::System(format!(
                "Payment request sent to {handle}: {} ZEC",
                zatoshi_to_zec_string(amount_zatoshi),
            )));
        }

        "payments" => {
            if state.sessions.is_empty() {
                state.push_message(ChatLine::System("No payment sessions.".to_string()));
            } else {
                use nie_core::messages::PaymentRole;
                use std::cmp::Reverse;
                let mut sessions: Vec<_> = state.sessions.values().cloned().collect();
                sessions.sort_by_key(|s| Reverse(s.created_at));
                for s in sessions {
                    let dir = match s.role {
                        PaymentRole::Payer => "→",
                        PaymentRole::Payee => "←",
                    };
                    state.push_message(ChatLine::System(format!(
                        "{dir} {} {} ZEC [{:?}]",
                        &s.id.to_string()[..8],
                        zatoshi_to_zec_string(s.amount_zatoshi),
                        s.state,
                    )));
                }
            }
        }

        _ => {
            state.push_message(ChatLine::System(format!(
                "Unknown command: /{cmd}. Type /help."
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AppState, ChatLine, OnlineUser};
    use nie_core::mls::MlsClient;

    fn make_state() -> AppState {
        let pub_id = "a".repeat(64);
        let mls = MlsClient::new(&pub_id).unwrap();
        AppState::new(pub_id, [0u8; 32], [0u8; 32], mls)
    }

    #[tokio::test]
    async fn reconnecting_resets_state() {
        let mut state = make_state();
        state.online.push(OnlineUser {
            pub_id: "b".repeat(64),
            nickname: None,
            sequence: 1,
        });
        state.mls_active = true;

        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        handle_relay_event(&mut state, &tx, ClientEvent::Reconnecting { delay_secs: 5 })
            .await
            .unwrap();

        assert_eq!(state.online.len(), 0);
        assert!(!state.mls_active);
        assert!(matches!(
            state.connection,
            ConnectionState::Reconnecting { delay_secs: 5 }
        ));
        assert!(matches!(state.messages.back(), Some(ChatLine::System(_))));
    }

    #[tokio::test]
    async fn reconnected_sets_connected() {
        let mut state = make_state();
        state.connection = ConnectionState::Reconnecting { delay_secs: 3 };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        handle_relay_event(&mut state, &tx, ClientEvent::Reconnected)
            .await
            .unwrap();
        assert_eq!(state.connection, ConnectionState::Connected);
    }

    #[tokio::test]
    async fn ctrl_c_sets_quit() {
        let mut state = make_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let key = crossterm::event::KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        handle_key(&mut state, &tx, key).await.unwrap();
        assert!(state.quit);
    }

    #[tokio::test]
    async fn char_insert_and_backspace() {
        let mut state = make_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        // Insert 'h', 'i'
        for c in ['h', 'i'] {
            handle_key(
                &mut state,
                &tx,
                crossterm::event::KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .await
            .unwrap();
        }
        assert_eq!(state.input, "hi");
        assert_eq!(state.input_cursor, 2);
        // Backspace
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert_eq!(state.input, "h");
        assert_eq!(state.input_cursor, 1);
    }

    #[tokio::test]
    async fn page_scroll() {
        let mut state = make_state();
        state.terminal_size = (80, 24);
        // Push enough messages to scroll
        for i in 0..100 {
            state.push_message(ChatLine::System(format!("msg {i}")));
        }
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert!(state.scroll_offset > 0);
        let offset_after_pgup = state.scroll_offset;
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert!(state.scroll_offset < offset_after_pgup);
    }

    // ---- Relay message handler tests ----

    #[tokio::test]
    async fn directory_list_rebuilds_online() {
        use nie_core::protocol::{DirectoryListParams, JsonRpcNotification, UserInfo};

        let mut state = make_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(16);

        let params = DirectoryListParams {
            online: vec![
                UserInfo {
                    pub_id: "b".repeat(64),
                    nickname: Some("bob".to_string()),
                    sequence: 1,
                },
                UserInfo {
                    pub_id: state.my_pub_id.clone(),
                    nickname: None,
                    sequence: 2,
                },
            ],
            offline: vec![],
        };
        let notif = JsonRpcNotification::new(rpc_methods::DIRECTORY_LIST, &params).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        assert_eq!(state.online.len(), 2);
        assert_eq!(state.online[0].pub_id, "b".repeat(64));
        assert_eq!(
            state.nicknames.get(&"b".repeat(64)),
            Some(&"bob".to_string())
        );
        assert!(state.ever_connected);
        assert_eq!(state.connection, ConnectionState::Connected);
    }

    #[tokio::test]
    async fn user_joined_inserts_in_sequence_order() {
        use nie_core::protocol::{JsonRpcNotification, UserJoinedParams};

        let mut state = make_state();
        // Pre-populate with sequence 1 and 3
        state.online.push(OnlineUser {
            pub_id: "aa".repeat(32),
            nickname: None,
            sequence: 1,
        });
        state.online.push(OnlineUser {
            pub_id: "cc".repeat(32),
            nickname: None,
            sequence: 3,
        });

        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let p = UserJoinedParams {
            pub_id: "bb".repeat(32),
            nickname: None,
            sequence: 2,
        };
        let notif = JsonRpcNotification::new(rpc_methods::USER_JOINED, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        assert_eq!(state.online.len(), 3);
        assert_eq!(state.online[0].sequence, 1);
        assert_eq!(state.online[1].sequence, 2);
        assert_eq!(state.online[2].sequence, 3);
    }

    #[tokio::test]
    async fn user_left_removes_from_online() {
        use nie_core::protocol::{JsonRpcNotification, UserLeftParams};

        let mut state = make_state();
        state.online.push(OnlineUser {
            pub_id: "b".repeat(64),
            nickname: None,
            sequence: 1,
        });

        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let p = UserLeftParams {
            pub_id: "b".repeat(64),
        };
        let notif = JsonRpcNotification::new(rpc_methods::USER_LEFT, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        assert_eq!(state.online.len(), 0);
    }

    #[tokio::test]
    async fn user_nickname_updates_cache() {
        use nie_core::protocol::{JsonRpcNotification, UserNicknameParams};

        let mut state = make_state();
        state.online.push(OnlineUser {
            pub_id: "b".repeat(64),
            nickname: None,
            sequence: 1,
        });

        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let p = UserNicknameParams {
            pub_id: "b".repeat(64),
            nickname: "alice".to_string(),
        };
        let notif = JsonRpcNotification::new(rpc_methods::USER_NICKNAME, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        assert_eq!(
            state.nicknames.get(&"b".repeat(64)),
            Some(&"alice".to_string())
        );
        assert_eq!(state.online[0].nickname, Some("alice".to_string()));
    }

    #[tokio::test]
    async fn deliver_plaintext_chat_appends_message() {
        use nie_core::protocol::{DeliverParams, JsonRpcNotification};

        let mut state = make_state();
        // mls_active = false — plaintext path
        let payload = serde_json::to_vec(&ClearMessage::Chat {
            text: "hello".to_string(),
        })
        .unwrap();
        let p = DeliverParams {
            from: "b".repeat(64),
            payload,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let notif = JsonRpcNotification::new(rpc_methods::DELIVER, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        assert!(matches!(
            state.messages.back(),
            Some(ChatLine::Chat { text, .. }) if text == "hello"
        ));
    }

    #[tokio::test]
    async fn deliver_unreadable_payload_pushes_system_message() {
        use nie_core::protocol::{DeliverParams, JsonRpcNotification};

        let mut state = make_state();
        let p = DeliverParams {
            from: "b".repeat(64),
            payload: b"not json".to_vec(),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let notif = JsonRpcNotification::new(rpc_methods::DELIVER, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        assert!(matches!(
            state.messages.back(),
            Some(ChatLine::System(s)) if s.contains("[!] unreadable")
        ));
    }

    #[tokio::test]
    async fn slash_iam_sends_request() {
        let mut state = make_state();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for c in "/iam alice".chars() {
            handle_key(
                &mut state,
                &tx,
                crossterm::event::KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .await
            .unwrap();
        }
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        let req = rx
            .try_recv()
            .expect("SetNickname request should have been sent");
        assert_eq!(req.method, rpc_methods::SET_NICKNAME);
        assert_eq!(
            state.own_profile.get("name").map(|s| s.as_str()),
            Some("alice")
        );
    }

    #[tokio::test]
    async fn slash_alias_stores_mapping() {
        let mut state = make_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let pub_id = "b".repeat(64);
        let cmd = format!("/alias bob {pub_id}");
        for c in cmd.chars() {
            handle_key(
                &mut state,
                &tx,
                crossterm::event::KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .await
            .unwrap();
        }
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert_eq!(
            state.local_names.get(&pub_id).map(|s| s.as_str()),
            Some("bob")
        );
    }

    #[tokio::test]
    async fn slash_bang_no_shell_injection() {
        // Verifies shlex splitting: semicolons are literal arguments, not shell separators.
        // /! echo hello — should run echo with arg "hello" and push output to chat.
        let mut state = make_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        for c in "/! echo hello".chars() {
            handle_key(
                &mut state,
                &tx,
                crossterm::event::KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .await
            .unwrap();
        }
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        // echo hello should produce a Chat message with "hello"
        assert!(state.messages.iter().any(|m| matches!(m,
            ChatLine::Chat { text, .. } if text.trim() == "hello"
        )));
    }

    // ---- is_valid_transition unit tests ----
    // Oracle: expected values derived from the documented state machine,
    // not from the implementation itself.

    #[test]
    fn valid_transitions_happy_path() {
        use nie_core::messages::{Chain, PaymentAction, PaymentRole, PaymentState};

        let addr_action = PaymentAction::Address {
            chain: Chain::Zcash,
            address: "zs1abc".to_string(),
        };
        let sent_action = PaymentAction::Sent {
            chain: Chain::Zcash,
            tx_hash: "deadbeef".to_string(),
            amount_zatoshi: 10_000_000, // 0.1 ZEC
        };
        let confirmed_action = PaymentAction::Confirmed {
            tx_hash: "deadbeef".to_string(),
        };

        // Payer in Requested receives Address → valid
        assert!(is_valid_transition(
            &PaymentState::Requested,
            &addr_action,
            &PaymentRole::Payer,
        ));

        // Payee in Requested receives Sent → valid
        assert!(is_valid_transition(
            &PaymentState::Requested,
            &sent_action,
            &PaymentRole::Payee,
        ));

        // Payer in AddressProvided receives Confirmed → valid
        assert!(is_valid_transition(
            &PaymentState::AddressProvided,
            &confirmed_action,
            &PaymentRole::Payer,
        ));
    }

    #[test]
    fn invalid_transitions_wrong_state() {
        use nie_core::messages::{Chain, PaymentAction, PaymentRole, PaymentState};

        let addr_action = PaymentAction::Address {
            chain: Chain::Zcash,
            address: "zs1abc".to_string(),
        };
        let confirmed_action = PaymentAction::Confirmed {
            tx_hash: "deadbeef".to_string(),
        };

        // Payer in AddressProvided receives another Address → invalid (already addressed)
        assert!(!is_valid_transition(
            &PaymentState::AddressProvided,
            &addr_action,
            &PaymentRole::Payer,
        ));

        // Payer in Requested receives Confirmed (skipped Address step) → invalid
        assert!(!is_valid_transition(
            &PaymentState::Requested,
            &confirmed_action,
            &PaymentRole::Payer,
        ));

        // Payee in Requested receives Address → invalid (wrong role)
        assert!(!is_valid_transition(
            &PaymentState::Requested,
            &addr_action,
            &PaymentRole::Payee,
        ));
    }

    #[test]
    fn terminal_states_block_transitions() {
        use nie_core::messages::{Chain, PaymentAction, PaymentRole, PaymentState};

        let addr_action = PaymentAction::Address {
            chain: Chain::Zcash,
            address: "zs1abc".to_string(),
        };
        let cancelled_action = PaymentAction::Cancelled {
            reason: "user cancelled".to_string(),
        };
        let unknown_action = PaymentAction::Unknown {
            reason: "session not found".to_string(),
        };

        // Confirmed (terminal) blocks Address
        assert!(!is_valid_transition(
            &PaymentState::Confirmed,
            &addr_action,
            &PaymentRole::Payer,
        ));

        // Expired (terminal) blocks Cancelled
        assert!(!is_valid_transition(
            &PaymentState::Expired,
            &cancelled_action,
            &PaymentRole::Payer,
        ));

        // Failed (terminal) blocks Cancelled
        assert!(!is_valid_transition(
            &PaymentState::Failed,
            &cancelled_action,
            &PaymentRole::Payee,
        ));

        // Unknown is always allowed (even from terminal state)
        assert!(is_valid_transition(
            &PaymentState::Confirmed,
            &unknown_action,
            &PaymentRole::Payer,
        ));
    }

    #[test]
    fn cancelled_allowed_from_any_non_terminal_state() {
        use nie_core::messages::{PaymentAction, PaymentRole, PaymentState};

        let cancelled_action = PaymentAction::Cancelled {
            reason: "changed mind".to_string(),
        };

        for state in [
            PaymentState::Requested,
            PaymentState::AddressProvided,
            PaymentState::Sent,
        ] {
            assert!(
                is_valid_transition(&state, &cancelled_action, &PaymentRole::Payer),
                "Cancelled should be valid from {state:?} as Payer"
            );
            assert!(
                is_valid_transition(&state, &cancelled_action, &PaymentRole::Payee),
                "Cancelled should be valid from {state:?} as Payee"
            );
        }
    }

    #[tokio::test]
    async fn payment_address_ignored_in_wrong_state() {
        use nie_core::messages::{Chain, PaymentAction, PaymentRole, PaymentState};
        use nie_core::protocol::{DeliverParams, JsonRpcNotification};

        let mut state = make_state();
        let session_id = uuid::Uuid::new_v4();

        // Insert a session that is already AddressProvided
        state.sessions.insert(
            session_id,
            nie_core::messages::PaymentSession {
                id: session_id,
                chain: nie_core::messages::Chain::Zcash,
                amount_zatoshi: 1_000_000,
                peer_pub_id: "b".repeat(64),
                role: PaymentRole::Payer,
                state: PaymentState::AddressProvided,
                created_at: 0,
                updated_at: 0,
                tx_hash: None,
                address: Some("zs1existing".to_string()),
            },
        );

        // Peer sends another Address action — should be ignored
        let payload = serde_json::to_vec(&ClearMessage::Payment {
            session_id,
            action: PaymentAction::Address {
                chain: Chain::Zcash,
                address: "zs1newaddress".to_string(),
            },
        })
        .unwrap();

        let p = DeliverParams {
            from: "b".repeat(64),
            payload,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let notif = JsonRpcNotification::new(rpc_methods::DELIVER, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        // Session address must remain unchanged
        let sess = state.sessions.get(&session_id).unwrap();
        assert_eq!(sess.address.as_deref(), Some("zs1existing"));
        assert_eq!(sess.state, PaymentState::AddressProvided);
    }

    #[tokio::test]
    async fn payment_confirmed_ignored_in_wrong_state() {
        use nie_core::messages::{PaymentAction, PaymentRole, PaymentState};
        use nie_core::protocol::{DeliverParams, JsonRpcNotification};

        let mut state = make_state();
        let session_id = uuid::Uuid::new_v4();

        // Insert a session that is still Requested (Address not yet received)
        state.sessions.insert(
            session_id,
            nie_core::messages::PaymentSession {
                id: session_id,
                chain: nie_core::messages::Chain::Zcash,
                amount_zatoshi: 1_000_000,
                peer_pub_id: "b".repeat(64),
                role: PaymentRole::Payer,
                state: PaymentState::Requested,
                created_at: 0,
                updated_at: 0,
                tx_hash: None,
                address: None,
            },
        );

        // Peer sends Confirmed before Address — must be ignored
        let payload = serde_json::to_vec(&ClearMessage::Payment {
            session_id,
            action: PaymentAction::Confirmed {
                tx_hash: "abc123".to_string(),
            },
        })
        .unwrap();

        let p = DeliverParams {
            from: "b".repeat(64),
            payload,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let notif = JsonRpcNotification::new(rpc_methods::DELIVER, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        // Session must remain Requested
        let sess = state.sessions.get(&session_id).unwrap();
        assert_eq!(sess.state, PaymentState::Requested);
        assert!(sess.tx_hash.is_none());
    }

    fn make_state_with_pub_id(pub_id: &str) -> AppState {
        let mls = MlsClient::new(pub_id).unwrap();
        AppState::new(pub_id.to_string(), [0u8; 32], [0u8; 32], mls)
    }

    fn gen_hpke_keypair() -> ([u8; 32], [u8; 32]) {
        use ::hpke::kem::X25519HkdfSha256;
        use ::hpke::{Kem as KemTrait, Serializable};
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let sk_bytes: [u8; 32] = sk.to_bytes().as_slice().try_into().unwrap();
        let pk_bytes: [u8; 32] = pk.to_bytes().as_slice().try_into().unwrap();
        (sk_bytes, pk_bytes)
    }

    #[tokio::test]
    async fn reconnecting_rebuilds_mls_client_with_own_pub_id() {
        let pub_id = "a".repeat(64);
        let mut state = make_state_with_pub_id(&pub_id);
        state.mls_active = true;
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        handle_relay_event(&mut state, &tx, ClientEvent::Reconnecting { delay_secs: 1 })
            .await
            .unwrap();
        assert_eq!(state.my_pub_id, pub_id);
        // New client must be usable (would fail if built with wrong identity)
        state
            .mls_client
            .key_package_bytes()
            .expect("post-reconnect MlsClient must be valid");
    }

    #[tokio::test]
    async fn sealed_deliver_before_mls_active_is_dropped() {
        use nie_core::protocol::{JsonRpcNotification, SealedDeliverParams};

        let (hpke_sk, hpke_pk) = gen_hpke_keypair();
        let mls = MlsClient::new(&"a".repeat(64)).unwrap();
        let mut state = AppState::new("a".repeat(64), hpke_sk, hpke_pk, mls);
        // MLS not yet active — sealed messages cannot be decrypted and must be dropped.
        state.mls_active = false;

        let plaintext = b"some sealed payload";
        let sealed = nie_core::hpke::seal_message(&hpke_pk, plaintext).unwrap();

        let p = SealedDeliverParams { sealed };
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let notif = JsonRpcNotification::new(rpc_methods::SEALED_DELIVER, &p).unwrap();
        let msg_count_before = state.messages.len();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        // No message must have been pushed — sealed message dropped before MLS join.
        assert_eq!(
            state.messages.len(),
            msg_count_before,
            "sealed_deliver before mls_active must be silently dropped"
        );
    }

    #[tokio::test]
    async fn delete_key_on_multibyte_char() {
        let mut state = make_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);

        // Insert '€' (3 bytes in UTF-8)
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Char('€'), KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert_eq!(state.input, "€");
        assert_eq!(state.input_cursor, 3);

        // Move cursor to start
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert_eq!(state.input_cursor, 0);

        // Delete — should remove the full '€' char without panic
        handle_key(
            &mut state,
            &tx,
            crossterm::event::KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE),
        )
        .await
        .unwrap();
        assert_eq!(state.input, "");
        assert_eq!(state.input_cursor, 0);
    }

    #[tokio::test]
    async fn payment_sent_ignored_for_payer_role() {
        use nie_core::messages::{Chain, PaymentAction, PaymentRole, PaymentState};
        use nie_core::protocol::{DeliverParams, JsonRpcNotification};

        let mut state = make_state();
        let session_id = uuid::Uuid::new_v4();

        // Insert a session with role=Payer, state=Requested
        state.sessions.insert(
            session_id,
            nie_core::messages::PaymentSession {
                id: session_id,
                chain: Chain::Zcash,
                amount_zatoshi: 1_000_000,
                peer_pub_id: "b".repeat(64),
                role: PaymentRole::Payer,
                state: PaymentState::Requested,
                created_at: 0,
                updated_at: 0,
                tx_hash: None,
                address: None,
            },
        );

        // Peer sends Sent action — Payer should not process it (wrong role)
        let payload = serde_json::to_vec(&ClearMessage::Payment {
            session_id,
            action: PaymentAction::Sent {
                chain: Chain::Zcash,
                tx_hash: "abc123".to_string(),
                amount_zatoshi: 1_000_000, // 0.01 ZEC
            },
        })
        .unwrap();

        let p = DeliverParams {
            from: "b".repeat(64),
            payload,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let notif = JsonRpcNotification::new(rpc_methods::DELIVER, &p).unwrap();
        handle_relay_event(&mut state, &tx, ClientEvent::Message(notif))
            .await
            .unwrap();

        // Session state must remain Requested
        let sess = state.sessions.get(&session_id).unwrap();
        assert_eq!(sess.state, PaymentState::Requested);
    }
}
