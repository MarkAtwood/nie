use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use age::secrecy::Secret;
use age::{Decryptor, Encryptor};
use anyhow::{bail, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use nie_core::hpke as nie_hpke;
use nie_core::identity::{Identity, PubId};
use nie_core::{parse_zec_to_zatoshi, zatoshi_to_zec_string};
use nie_core::messages::{
    Chain, ClearMessage, PaymentAction, PaymentRole, PaymentSession, PaymentState,
};
use nie_core::mls::MlsClient;
use nie_core::protocol::{
    rpc_methods, BroadcastParams, GetKeyPackageParams, GroupCreateParams, GroupCreateResult,
    GroupDeliverParams, GroupLeaveParams, GroupListResult, GroupSendParams, JsonRpcRequest,
    PublishHpkeKeyParams, PublishKeyPackageParams, SealedBroadcastParams, SealedDeliverParams,
    SealedWhisperDeliverParams, SetNicknameParams, SubscribeInvoiceResult, SubscribeRequestParams,
    SubscriptionActiveParams, WhisperParams,
};
use nie_core::transport::{self, next_request_id, ClientEvent};
use uuid::Uuid;

use crate::config::Contacts;
use crate::history::History;

/// Event sent from the background confirmation watcher to the main chat loop.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ConfirmationEvent {
    pub session_id: uuid::Uuid,
    pub txid: String,
    pub block_height: u64,
}

/// Thread-safe registry mapping watched Sapling address → payment session UUID.
///
/// The background watcher task holds an `Arc<AddressWatchRegistry>` and calls
/// `lookup` for every compact block output. The main chat task registers and
/// deregisters addresses as payment sessions enter/leave the waiting state.
#[allow(dead_code)]
pub struct AddressWatchRegistry(dashmap::DashMap<String, uuid::Uuid>);

#[allow(dead_code)]
impl AddressWatchRegistry {
    pub fn new() -> Self {
        Self(dashmap::DashMap::new())
    }

    /// Register `address` as a watched address for `session_id`.
    /// Overwrites any previous registration for the same address (idempotent).
    pub fn register(&self, address: String, session_id: uuid::Uuid) {
        self.0.insert(address, session_id);
    }

    /// Remove `address` from the watch list. No-op if not registered.
    pub fn deregister(&self, address: &str) {
        self.0.remove(address);
    }

    /// Return the session UUID for `address`, or `None` if not registered.
    pub fn lookup(&self, address: &str) -> Option<uuid::Uuid> {
        self.0.get(address).map(|v| *v)
    }

    /// Number of registered addresses (for logging/metrics).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

use nie_wallet::address::{SaplingDiversifiableFvk, SaplingExtendedSpendingKey, ZcashNetwork};
use nie_wallet::client::{DEFAULT_MAINNET_ENDPOINTS, DEFAULT_TESTNET_ENDPOINT};
use nie_wallet::db::WalletStore;
use nie_wallet::fees::{sapling_logical_actions, zip317_fee};
use nie_wallet::orchard::{OrchardFullViewingKey, OrchardSpendingKey};
use nie_wallet::params::SaplingParamPaths;
use nie_wallet::payment::{send_payment, SendPaymentError};
use nie_wallet::scanner::{NoteDecryptor, SaplingIvkDecryptor};
use nie_wallet::tx_builder::{load_sapling_params, DUST_THRESHOLD};
use nie_wallet::unified::{decode_unified_address, diversified_address, sapling_receiver};

// ---- Identity management ----

pub async fn init(keyfile: &str, no_passphrase: bool) -> Result<()> {
    if std::path::Path::new(keyfile).exists() {
        bail!("keyfile already exists at {keyfile}. Delete it to start fresh.");
    }
    let id = Identity::generate();
    let seed = id.to_secret_bytes_64();

    let passphrase = if no_passphrase {
        eprintln!("WARNING: --no-passphrase set. Identity key will NOT be encrypted.");
        String::new()
    } else {
        let p = rpassword::prompt_password("Passphrase: ")?;
        let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
        anyhow::ensure!(p == p2, "passphrases do not match");
        p
    };

    let encrypted = encrypt_keyfile(&seed, &passphrase)?;
    std::fs::write(keyfile, &encrypted)?;

    println!("identity created");
    println!("public id  : {}", id.pub_id().0);
    println!("keyfile    : {keyfile}");
    println!();
    println!("Back up your keyfile. If you lose it, your identity is gone.");
    Ok(())
}

pub async fn whoami(keyfile: &str, no_passphrase: bool) -> Result<()> {
    let id = load_identity(keyfile, no_passphrase)?;
    println!("{}", id.pub_id().0);
    Ok(())
}

// ---- Chat ----

/// Show local message history.
pub async fn log(data_dir: &Path, limit: i64) -> Result<()> {
    let history = History::open(data_dir).await?;
    let entries = history.recent(limit).await?;
    if entries.is_empty() {
        println!("(no history)");
        return Ok(());
    }
    for e in &entries {
        let short_from = PubId(e.from_pub_id.clone()).short();
        let dir_marker = if e.direction == "sent" { "→" } else { "←" };
        println!(
            "[{}] {} {}: {}",
            e.timestamp,
            dir_marker,
            short_from,
            String::from_utf8_lossy(&e.payload)
        );
    }
    Ok(())
}

/// Client-side state for a named group channel.
struct GroupClientState {
    name: String,
}

/// Join the multiuser chat room, with automatic reconnection on disconnect.
///
/// MLS integration: on connect we publish a key package.  The admin (first in
/// the online list) creates the group and adds every new joiner.  Non-admins
/// join via a Welcome whisper.  All chat messages are MLS-encrypted; received
/// payloads are decrypted before display.  MLS Commits (adds/removes) update
/// group state silently.  Group state is ephemeral — each `chat` session
/// starts fresh.
#[allow(clippy::too_many_arguments)]
pub async fn chat(
    keyfile: &str,
    data_dir: &Path,
    relay_url: &str,
    insecure: bool,
    no_passphrase: bool,
    network: &str,
    lightwalletd: Option<String>,
    proxy: Option<String>,
) -> Result<()> {
    let id = load_identity(keyfile, no_passphrase)?;
    let my_pub_id = id.pub_id().0;
    // Extract HPKE keypair before `id` is moved into the transport layer.
    // hpke_secret_bytes() must never be logged — see security checklist item 1.
    let hpke_identity_secret: [u8; 32] = id.hpke_secret_bytes();
    let hpke_identity_pub: [u8; 32] = id.hpke_pub_key_bytes();

    let history = History::open(data_dir).await?;
    let wallet_store = WalletStore::new(&data_dir.join("wallet.db")).await?;
    // Ensure the payment account row exists once at startup, not on every request.
    // If this fails, payment address generation is disabled for the session so that
    // subsequent payment requests fail at the wallet-capability gate rather than with
    // a cryptic "account not found" error from next_diversifier.
    let wallet_fvks = match try_load_wallet_fvks(data_dir, no_passphrase, network) {
        None => None,
        Some(fvks) => match wallet_store.ensure_account(PAYMENT_ACCOUNT).await {
            Ok(()) => Some(fvks),
            Err(e) => {
                eprintln!("[wallet] Failed to initialize payment account: {e}");
                eprintln!("[wallet] Payment address generation disabled for this session.");
                warn!("ensure_account at startup failed: {e}");
                None
            }
        },
    };

    // Build the payment-send closure from wallet context.
    // Sapling proving parameters (~51 MB) are loaded once here and Arc-shared
    // across all payments, avoiding per-payment disk I/O.
    // A new lightwalletd connection is made on every call rather than holding a
    // persistent LightwalletdClient, which would require Arc<Mutex<...>> to be
    // shared safely across await points in the chat event loop.
    let send_fn_box: Option<Box<SendFn>> = if let Some(ref fvks) = wallet_fvks {
        let sk = Arc::clone(&fvks.sapling_sk);
        let store = wallet_store.clone();
        let network = fvks.network;
        // Use the full endpoint slice so connect_with_failover can try alternatives
        // if the first endpoint is unreachable.  The user-supplied override (if any)
        // is used exclusively; otherwise the network defaults are used.
        let lwd_endpoints = resolve_lwd_endpoints(lightwalletd.as_deref(), network);
        let params_dir = std::env::var("ZCASH_PARAMS")
            .ok()
            .map(std::path::PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".zcash-params")))
            .unwrap_or_else(|| std::path::PathBuf::from(".zcash-params"));
        let params_paths = SaplingParamPaths {
            spend: params_dir.join("sapling-spend.params"),
            output: params_dir.join("sapling-output.params"),
        };
        match load_sapling_params(&params_paths) {
            Err(e) => {
                tracing::warn!(
                    "Sapling params not found at {}: {e} — auto-payment disabled",
                    params_dir.display()
                );
                eprintln!(
                    "[wallet] Sapling params not found at {} ({e}).\n\
                     Auto-payment is disabled. Copy sapling-spend.params and \
                     sapling-output.params there, then restart.\n\
                     To send manually: use /confirm <session-id> after a payment request.",
                    params_dir.display()
                );
                None
            }
            Ok(loaded) => {
                let params_arc = Arc::new(loaded);
                Some(Box::new(move |address: String, amount: u64, sid: Uuid| {
                    let sk = Arc::clone(&sk);
                    let store = store.clone();
                    let params = Arc::clone(&params_arc);
                    let endpoints = lwd_endpoints.clone();
                    Box::pin(async move {
                        let endpoint_refs: Vec<&str> =
                            endpoints.iter().map(String::as_str).collect();
                        let mut client = nie_wallet::client::connect_with_failover(&endpoint_refs)
                            .await
                            .map_err(SendPaymentError::Connect)?;
                        send_payment(
                            &sk,
                            &address,
                            amount,
                            sid,
                            &store,
                            &mut client,
                            Some(&*params),
                            network,
                        )
                        .await
                    })
                }))
            }
        }
    } else {
        None
    };

    println!("connecting to {relay_url}...");
    let conn = transport::connect_with_retry(relay_url.to_string(), id, insecure, proxy);
    let tx: tokio::sync::mpsc::Sender<JsonRpcRequest> = conn.tx;
    let mut rx = conn.rx;

    // Per-session MLS state.
    let mut mls = MlsClient::new(&my_pub_id)?;
    // Ordered list of currently online pub_ids.  First entry (lowest sequence) is admin.
    // Maintained in connection_seq ascending order so online[0] is consistent across
    // all peers regardless of UserJoined event arrival order.
    let mut online: Vec<String> = Vec::new();
    // Maps pub_id → relay connection_seq for online users.  Used to insert new
    // joiners at the correct sorted position in `online`.
    let mut online_seq: HashMap<String, u64> = HashMap::new();
    let mut mls_active = false;
    // Sealed sender state.  room_hpke_* is derived from MLS export_secret once
    // the group is active; before that we fall back to identity-level HPKE.
    // Neither field is ever logged — only public keys (room_hpke_pub) are safe to log.
    let mut room_hpke_secret: Option<[u8; 32]> = None;
    let mut room_hpke_pub: Option<[u8; 32]> = None;
    let mut nicknames: HashMap<String, String> = HashMap::new();
    let mut ever_connected = false;

    // Own profile fields (persisted to profile.json, broadcast to room on connect).
    let mut own_profile: HashMap<String, String> = crate::profile::load(data_dir);
    // Most-recent profile broadcast received per peer; keyed by pub_id.
    let mut peer_profiles: HashMap<String, HashMap<String, String>> = HashMap::new();

    // Whether the first MLS resync of this connect cycle has been done.
    // Set false on reconnect so we re-resync after the next MLS activation.
    let mut sessions_resynced = false;
    // Named group channels: group_id → GroupClientState.
    // Populated by GROUP_CREATE and GROUP_LIST responses; cleared on reconnect.
    let mut active_groups: HashMap<String, GroupClientState> = HashMap::new();

    // Payment sessions: session_id → PaymentSession.
    // Loaded from wallet DB on startup (nie-421); persisted on every state change (nie-z5x).
    let stored_sessions = wallet_store.all_sessions().await.unwrap_or_else(|e| {
        warn!("failed to load payment sessions from DB: {e}");
        vec![]
    });
    if !stored_sessions.is_empty() {
        println!(
            "[pay] {} payment session(s) restored from disk",
            stored_sessions.len()
        );
    }
    let mut sessions: HashMap<Uuid, PaymentSession> =
        stored_sessions.into_iter().map(|s| (s.id, s)).collect();

    // Expire sessions that have not advanced within 24 hours (nie-0bj).
    // Terminal sessions (Confirmed/Failed/Expired) are unchanged.
    // One bulk SQL UPDATE instead of N individual upsert_session calls.
    let now_ts = chrono::Utc::now().timestamp();
    let expire_cutoff = now_ts - 24 * 3600;
    match wallet_store
        .expire_sessions_older_than(now_ts, 24 * 3600)
        .await
    {
        Ok(n) if n > 0 => {
            println!("[pay] {n} session(s) expired (no activity for 24h).");
            // Sync in-memory state to match the DB update.
            for session in sessions.values_mut() {
                if !matches!(
                    session.state,
                    PaymentState::Confirmed | PaymentState::Failed | PaymentState::Expired
                ) && session.updated_at < expire_cutoff
                {
                    session.state = PaymentState::Expired;
                    session.updated_at = now_ts;
                }
            }
        }
        Ok(_) => {}
        Err(e) => warn!("failed to expire stale sessions: {e}"),
    }

    // Local contact aliases: pub_id → name. Loaded from contacts.json.
    // Lower priority than server /iam nicknames. Never cleared during session.
    let mut contacts = Contacts::load(data_dir).unwrap_or_default();
    let mut local_names: HashMap<String, String> = contacts
        .entries
        .iter()
        .map(|c| (c.pubkey.clone(), c.name.clone()))
        .collect();

    let (line_tx, mut line_rx) = mpsc::channel::<String>(8);
    tokio::task::spawn_blocking(move || {
        let mut rl = match rustyline::DefaultEditor::new() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("readline init failed: {e}");
                return;
            }
        };
        while let Ok(line) = rl.readline("> ") {
            let _ = rl.add_history_entry(line.as_str());
            if line_tx.blocking_send(line).is_err() {
                break;
            }
        }
    });

    // Confirmation events from the background block watcher (nie-ghf).
    let (conf_tx, mut conf_rx) = tokio::sync::mpsc::channel::<ConfirmationEvent>(32);

    // Restore any active payment sessions into the watch registry on startup (nie-fc4).
    // The registry key is hex(Sapling address bytes) so the watcher can match decrypted
    // payment addresses without storing or logging Unified Address strings.
    let watch_registry = std::sync::Arc::new(AddressWatchRegistry::new());
    match wallet_store.sessions_to_watch().await {
        Ok(sessions) => {
            let n = sessions.len();
            for session in sessions {
                if let Some(ua_str) = session.address {
                    if let Ok((_net, ua)) = decode_unified_address(&ua_str) {
                        if let Some(sapling_bytes) = sapling_receiver(&ua) {
                            let key: String =
                                sapling_bytes.iter().map(|b| format!("{b:02x}")).collect();
                            watch_registry.register(key, session.id);
                        }
                    }
                }
            }
            if n > 0 {
                debug!("restored {n} watching sessions into watcher registry");
            }
        }
        Err(e) => {
            warn!("failed to restore watching sessions: {e}");
        }
    }

    // Spawn the background block watcher (nie-ghf) if the wallet is initialized.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let _watcher_handle = if let Some(ref fvks) = wallet_fvks {
        let lwd_endpoints = resolve_lwd_endpoints(lightwalletd.as_deref(), fvks.network);
        Some(spawn_block_watcher(
            fvks.sapling.ivk_bytes(),
            watch_registry.clone(),
            conf_tx,
            lwd_endpoints,
            shutdown_rx,
        ))
    } else {
        None
    };

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break };

                match event {
                    // ---- Connection state ----
                    ClientEvent::Reconnecting { delay_secs } => {
                        println!("\r[!] disconnected. reconnecting in {delay_secs}s...");
                        if mls_active {
                            println!("\r[MLS] session reset");
                        }
                        mls_active = false;
                        room_hpke_secret = None;
                        room_hpke_pub = None;
                        sessions_resynced = false;
                        online.clear();
                        online_seq.clear();
                        active_groups.clear();
                        // Reset MLS client so the reconnected session gets a fresh OpenMLS
                        // provider.  Without this, create_group() returns GroupAlreadyExists
                        // on reconnect (openmls checks its storage before writing) and the
                        // admin cannot encrypt messages in the new session.
                        mls = MlsClient::new(&my_pub_id)?;
                    }
                    ClientEvent::Reconnected => {
                        println!("\r[!] reconnected");
                    }

                    // ---- Directory ----
                    ClientEvent::Message(notif)
                        if notif.method == rpc_methods::DIRECTORY_LIST =>
                    {
                        let params: nie_core::protocol::DirectoryListParams = serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        )
                        .unwrap_or_else(|e| {
                            warn!("failed to parse directory_list params: {e}");
                            nie_core::protocol::DirectoryListParams {
                                online: vec![],
                                offline: vec![],
                            }
                        });
                        let ol = params.online;
                        let offline = params.offline;
                        // Rebuild nickname cache first so scrollback and directory can use it.
                        nicknames.clear();
                        for u in ol.iter().chain(offline.iter()) {
                            if let Some(n) = &u.nickname {
                                nicknames.insert(u.pub_id.clone(), n.clone());
                            }
                        }

                        if !ever_connected {
                            ever_connected = true;
                            println!(
                                "connected. type to chat, /iam <name> to set nickname, Ctrl-C to quit."
                            );
                            // Print recent history so the user has context.
                            match history.recent(50).await {
                                Ok(entries) if !entries.is_empty() => {
                                    println!("--- last {} messages ---", entries.len());
                                    for e in &entries {
                                        let text = String::from_utf8_lossy(&e.payload);
                                        let formatted = if let Some(inner) = text
                                            .strip_prefix("\x01ACTION ")
                                            .and_then(|s| s.strip_suffix('\x01'))
                                        {
                                            format!(
                                                "* {} {}",
                                                colored_name(&e.from_pub_id, &nicknames, &local_names),
                                                inner
                                            )
                                        } else {
                                            format!(
                                                "{}: {}",
                                                colored_name(&e.from_pub_id, &nicknames, &local_names),
                                                text
                                            )
                                        };
                                        println!("[{}] {}", format_ts(e.timestamp), formatted);
                                    }
                                    println!("--- end of history ---\n");
                                }
                                Ok(_) => println!(),
                                Err(e) => warn!("history.recent: {e}"),
                            }
                        }

                        // Rebuild online list from the relay-ordered DirectoryList.
                        // The relay sorts online users by connection_seq ascending, so
                        // online[0] here is the earliest-connected client = admin.
                        // online_seq is populated so subsequent UserJoined events can
                        // insert at the correct sorted position (nie-8le.1 fix).
                        online_seq.clear();
                        for u in &ol {
                            online_seq.insert(u.pub_id.clone(), u.sequence);
                        }
                        online = ol.iter().map(|u| u.pub_id.clone()).collect();
                        let i_am_admin = is_admin(&online, &my_pub_id);

                        println!("--- directory ---");
                        for u in &ol {
                            let name = display_name(&u.pub_id, &nicknames, &local_names);
                            let marker = if u.pub_id == my_pub_id { " (you)" } else { "" };
                            println!("  online  {}{}", name, marker);
                        }
                        for u in &offline {
                            println!("  offline {}", display_name(&u.pub_id, &nicknames, &local_names));
                        }
                        println!("--- {} online, {} known ---\n", ol.len(), ol.len() + offline.len());

                        // Publish key package so admin can add us.
                        match mls.key_package_bytes() {
                            Ok(kp) => {
                                let req = JsonRpcRequest::new(
                                    next_request_id(),
                                    rpc_methods::PUBLISH_KEY_PACKAGE,
                                    PublishKeyPackageParams { data: kp },
                                )
                                .unwrap();
                                if tx.send(req).await.is_err() {
                                    eprintln!("connection lost.");
                                    break;
                                }
                            }
                            Err(e) => warn!("key_package_bytes: {e}"),
                        }

                        // Publish our HPKE public key so peers can send us sealed messages.
                        // We always publish the identity-level key on connect; once MLS is
                        // active we will overwrite this with the room-derived key.
                        {
                            let req = JsonRpcRequest::new(
                                next_request_id(),
                                rpc_methods::PUBLISH_HPKE_KEY,
                                PublishHpkeKeyParams { public_key: hpke_identity_pub.to_vec() },
                            )
                            .unwrap();
                            if tx.send(req).await.is_err() {
                                eprintln!("connection lost.");
                                break;
                            }
                        }

                        // Broadcast own profile so peers see our self-description.
                        if !send_profile_broadcast(&tx, &own_profile, mls_active, &mut mls).await {
                            eprintln!("connection lost.");
                            break;
                        }

                        // Admin with empty group: create it now.
                        if i_am_admin && !mls_active {
                            match mls.create_group() {
                                Ok(()) => {
                                    mls_active = true;
                                    println!(
                                        "\r[MLS] group created — epoch {}",
                                        mls.epoch().unwrap_or(0)
                                    );
                                    // Derive room HPKE keypair from MLS export_secret and
                                    // publish the room public key so peers seal to us
                                    // with the epoch-bound key rather than the identity key.
                                    match mls.room_hpke_keypair() {
                                        Ok((room_sk, room_pk)) => {
                                            room_hpke_secret = Some(room_sk);
                                            room_hpke_pub = Some(room_pk);
                                            let req = JsonRpcRequest::new(
                                                next_request_id(),
                                                rpc_methods::PUBLISH_HPKE_KEY,
                                                PublishHpkeKeyParams { public_key: room_pk.to_vec() },
                                            )
                                            .unwrap();
                                            if tx.send(req).await.is_err() {
                                                eprintln!("connection lost.");
                                                break;
                                            }
                                            tracing::debug!(
                                                "published room HPKE key for epoch {}",
                                                mls.epoch().unwrap_or(0)
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!("failed to derive room HPKE keypair after MLS activation: {e}");
                                        }
                                    }
                                    // Re-broadcast profile now that MLS is active so it travels
                                    // encrypted.  The pre-MLS broadcast above was plaintext.
                                    if !send_profile_broadcast(&tx, &own_profile, mls_active, &mut mls).await {
                                        eprintln!("connection lost.");
                                        break;
                                    }
                                    // nie-0aj: resync in-flight sessions so peers see our
                                    // last message even if we restarted mid-negotiation.
                                    if !sessions_resynced {
                                        sessions_resynced = true;
                                        if !resync_sessions(&sessions, &online, &tx, &mut mls).await {
                                            eprintln!("connection lost.");
                                            break;
                                        }
                                    }
                                }
                                Err(e) => warn!("create_group: {e}"),
                            }
                        }
                    }

                    // ---- Peer joined ----
                    ClientEvent::Message(notif) if notif.method == rpc_methods::USER_JOINED => {
                        let p: nie_core::protocol::UserJoinedParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("failed to parse user_joined params: {e}");
                                continue;
                            }
                        };
                        let pub_id = p.pub_id;
                        let nickname = p.nickname;
                        let sequence = p.sequence;
                        if let Some(n) = nickname {
                            nicknames.insert(pub_id.clone(), n);
                        }
                        // Insert at the position that maintains ascending sequence order.
                        // This ensures online[0] (admin) is consistent across all peers
                        // even when UserJoined events arrive in different orders due to
                        // concurrent connections on the relay.
                        online_seq.insert(pub_id.clone(), sequence);
                        let pos = online.partition_point(|id| {
                            online_seq.get(id).copied().unwrap_or(u64::MAX) < sequence
                        });
                        online.insert(pos, pub_id.clone());
                        let marker = if pub_id == my_pub_id { " (you)" } else { "" };
                        println!(
                            "\r[+] {}{}",
                            colored_name(&pub_id, &nicknames, &local_names),
                            marker
                        );

                        // Republish our key package only if we are not yet in the MLS
                        // group (waiting for a Welcome).  Once mls_active is true the
                        // admin has already added us and holds our KP — republishing
                        // every UserJoined would generate O(N²) publishes per session
                        // with no benefit (nie-8le.6).  New joiners always have a higher
                        // sequence number than us, so they can never become the admin
                        // for an already-established group.
                        if !mls_active {
                            match mls.key_package_bytes() {
                                Ok(kp) => {
                                    let req = JsonRpcRequest::new(
                                        next_request_id(),
                                        rpc_methods::PUBLISH_KEY_PACKAGE,
                                        PublishKeyPackageParams { data: kp },
                                    )
                                    .unwrap();
                                    if tx.send(req).await.is_err() {
                                        eprintln!("connection lost.");
                                        break;
                                    }
                                }
                                Err(e) => warn!("key_package_bytes on UserJoined: {e}"),
                            }
                        }

                        // Republish own profile so the new joiner gets our self-description.
                        if !send_profile_broadcast(&tx, &own_profile, mls_active, &mut mls).await {
                            eprintln!("connection lost.");
                            break;
                        }
                    }

                    // ---- Peer left ----
                    ClientEvent::Message(notif) if notif.method == rpc_methods::USER_LEFT => {
                        let p: nie_core::protocol::UserLeftParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("failed to parse user_left params: {e}");
                                continue;
                            }
                        };
                        let pub_id = p.pub_id;
                        online.retain(|id| id != &pub_id);
                        online_seq.remove(&pub_id);
                        println!("\r[-] {} left", colored_name(&pub_id, &nicknames, &local_names));

                        // Admin (possibly newly promoted): remove departed member.
                        let i_am_admin = is_admin(&online, &my_pub_id);
                        if i_am_admin && mls_active {
                            // Only attempt removal if the peer was actually added to the group.
                            // Race: UserLeft can arrive before KeyPackageResponse completes the
                            // add, so the peer never made it into the group — silently skip.
                            if mls.group_contains(&pub_id) {
                                match mls.remove_member(&pub_id) {
                                    Ok(commit) => {
                                        let padded_commit = match nie_core::messages::pad(&commit) {
                                            Ok(p) => p,
                                            Err(e) => {
                                                warn!("remove_member commit pad failed: {e}");
                                                continue;
                                            }
                                        };
                                        let req = JsonRpcRequest::new(
                                            next_request_id(),
                                            rpc_methods::BROADCAST,
                                            BroadcastParams { payload: padded_commit },
                                        )
                                        .unwrap();
                                        if tx.send(req).await.is_err() {
                                            eprintln!("connection lost.");
                                            break;
                                        }
                                        println!(
                                            "\r[MLS] {} removed — epoch {}",
                                            colored_name(&pub_id, &nicknames, &local_names),
                                            mls.epoch().unwrap_or(0)
                                        );
                                    }
                                    Err(e) => warn!("remove_member {pub_id}: {e}"),
                                }
                            }
                        }
                    }

                    // ---- Key package ready (relay stored a key package) ----
                    // The relay broadcasts this after the write, establishing a
                    // happens-before edge: our GetKeyPackage is guaranteed to find
                    // the stored package.  Admin uses this to add new members.
                    ClientEvent::Message(notif)
                        if notif.method == rpc_methods::KEY_PACKAGE_READY =>
                    {
                        let p: nie_core::protocol::KeyPackageReadyParams =
                            match serde_json::from_value(
                                notif.params.unwrap_or(serde_json::Value::Null),
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!("failed to parse key_package_ready params: {e}");
                                    continue;
                                }
                            };
                        let ready_id = p.pub_id;
                        let i_am_admin = is_admin(&online, &my_pub_id);
                        if i_am_admin && mls_active && ready_id != my_pub_id && !mls.group_contains(&ready_id) {
                            let req = JsonRpcRequest::new(
                                next_request_id(),
                                rpc_methods::GET_KEY_PACKAGE,
                                GetKeyPackageParams { pub_id: ready_id },
                            )
                            .unwrap();
                            if tx.send(req).await.is_err() {
                                eprintln!("connection lost.");
                                break;
                            }
                        }
                    }

                    // ---- Key package response (admin adds new member) ----
                    // The relay sends GetKeyPackage results as JsonRpcResponse (has id).
                    // The relay also sends SubscribeRequest results this way.
                    ClientEvent::Response(resp) => {
                        // Try to decode as SubscribeInvoiceResult first.
                        if let Some(ref result_val) = resp.result {
                            if let Ok(invoice) = serde_json::from_value::<SubscribeInvoiceResult>(result_val.clone()) {
                                if !invoice.address.is_empty() {
                                    println!("[subscribe] Invoice created:");
                                    println!("  Address:  {}", invoice.address);
                                    println!(
                                        "  Amount:   {} ZEC  ({} zatoshi)",
                                        zatoshi_to_zec_string(invoice.amount_zatoshi),
                                        invoice.amount_zatoshi
                                    );
                                    println!("  Expires:  {}", invoice.expires_at);
                                    println!("  Send payment to the address above to activate subscription.");
                                    continue;
                                }
                            }
                        }
                        // Try GroupCreateResult: { group_id, name }.
                        if let Some(ref result_val) = resp.result {
                            if let Ok(gc) = serde_json::from_value::<GroupCreateResult>(result_val.clone()) {
                                if !gc.group_id.is_empty() {
                                    let short = &gc.group_id[..gc.group_id.len().min(8)];
                                    println!("[group] Created '{}' (id: {short})", gc.name);
                                    active_groups.insert(
                                        gc.group_id,
                                        GroupClientState { name: gc.name },
                                    );
                                    continue;
                                }
                            }
                        }
                        // Try GroupListResult: { groups: [...] }.
                        if let Some(ref result_val) = resp.result {
                            if let Ok(gl) = serde_json::from_value::<GroupListResult>(result_val.clone()) {
                                // Only treat it as a list response if groups field is present
                                // (serde gives us an empty Vec for missing field with default).
                                // Use the discriminator: GroupListResult serializes with "groups" key.
                                if result_val.get("groups").is_some() {
                                    active_groups.clear();
                                    if gl.groups.is_empty() {
                                        println!("[group] No groups.");
                                    } else {
                                        for g in &gl.groups {
                                            let short = &g.group_id[..g.group_id.len().min(8)];
                                            println!(
                                                "[group] {} — {} member(s)  (id: {short})",
                                                g.name, g.member_count
                                            );
                                            active_groups.insert(
                                                g.group_id.clone(),
                                                GroupClientState { name: g.name.clone() },
                                            );
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                        // Decode as GetKeyPackageResult; ignore responses for other requests.
                        let kp_result: nie_core::protocol::GetKeyPackageResult =
                            match resp.result.and_then(|v| serde_json::from_value(v).ok()) {
                                Some(r) => r,
                                None => continue,
                            };
                        let target_id = kp_result.pub_id;
                        match kp_result.data {
                            Some(kp_data) => {
                                let i_am_admin = is_admin(&online, &my_pub_id);
                                // group_contains is a belt-and-suspenders check: KeyPackageReady
                                // already filters out existing members, but republication on
                                // UserJoined could theoretically race a concurrent add.
                                if i_am_admin && mls_active && !mls.group_contains(&target_id) {
                                    match mls.add_member(&kp_data) {
                                        Ok((commit_bytes, welcome_bytes)) => {
                                            // Broadcast Commit so all existing members advance epoch.
                                            let padded_commit = match nie_core::messages::pad(&commit_bytes) {
                                                Ok(p) => p,
                                                Err(e) => {
                                                    warn!("add_member commit pad failed: {e}");
                                                    continue;
                                                }
                                            };
                                            // If this send fails, nothing has been delivered — safe to break.
                                            let commit_req = JsonRpcRequest::new(
                                                next_request_id(),
                                                rpc_methods::BROADCAST,
                                                BroadcastParams { payload: padded_commit },
                                            )
                                            .unwrap();
                                            if tx.send(commit_req).await.is_err() {
                                                eprintln!("connection lost.");
                                                break;
                                            }
                                            // Whisper Welcome to the new member.
                                            // IMPORTANT: the Commit above already reached the relay and
                                            // will advance every existing member's epoch.  If this send
                                            // fails, the new member is in the group state but will never
                                            // receive a Welcome — they cannot decrypt until they reconnect
                                            // and trigger a fresh add.  This is a known at-most-once
                                            // limitation (see nie-8le.2); at-least-once delivery with
                                            // retransmission of saved Welcome bytes is Phase 2 work.
                                            let whisper_req = JsonRpcRequest::new(
                                                next_request_id(),
                                                rpc_methods::WHISPER,
                                                WhisperParams {
                                                    to: target_id.clone(),
                                                    payload: welcome_bytes,
                                                },
                                            )
                                            .unwrap();
                                            if tx.send(whisper_req).await.is_err() {
                                                // Do not break — the admin is still connected and the
                                                // other members' epoch is valid.  Surface the failure so
                                                // the user can ask the affected peer to reconnect.
                                                eprintln!(
                                                    "\r[MLS] WARNING: Commit delivered but Welcome to {} \
                                                     failed — they are in group state but cannot decrypt. \
                                                     Ask them to reconnect.",
                                                    colored_name(&target_id, &nicknames, &local_names)
                                                );
                                            } else {
                                                println!(
                                                    "\r[MLS] {} added — epoch {}",
                                                    colored_name(&target_id, &nicknames, &local_names),
                                                    mls.epoch().unwrap_or(0)
                                                );
                                            }
                                        }
                                        Err(e) => warn!("add_member {target_id}: {e}"),
                                    }
                                }
                            }
                            None => {
                                // The relay returned None: the peer hasn't published a key package
                                // yet, or it was deleted/expired.  Surface this so the user knows
                                // why the peer wasn't added.  The peer will republish on UserJoined,
                                // triggering a fresh GetKeyPackage → response cycle.
                                warn!("key package for {target_id} not available; member will not be added");
                                eprintln!(
                                    "\r[MLS] key package for {} not available — \
                                     ask them to reconnect to retry.",
                                    colored_name(&target_id, &nicknames, &local_names)
                                );
                            }
                        }
                    }

                    // ---- WhisperDeliver: DM or MLS Welcome ----
                    // Dispatch on content type: JSON ClearMessage → display as DM;
                    // binary (non-JSON) → treat as MLS Welcome.
                    ClientEvent::Message(notif) if notif.method == rpc_methods::WHISPER_DELIVER => {
                        let p: nie_core::protocol::WhisperDeliverParams =
                            match serde_json::from_value(
                                notif.params.unwrap_or(serde_json::Value::Null),
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!("failed to parse whisper_deliver params: {e}");
                                    continue;
                                }
                            };
                        let from = p.from.clone();
                        let payload = p.payload;
                        match serde_json::from_slice::<ClearMessage>(&payload) {
                            Ok(ClearMessage::Chat { text }) => {
                                let ts = Local::now().format("%H:%M");
                                let name = colored_name(&from, &nicknames, &local_names);
                                println!("\r[{ts}] DM from {name}: {text}");
                            }
                            Ok(_) => {
                                warn!("unexpected ClearMessage type in WhisperDeliver from {from}");
                            }
                            Err(_) => {
                                // Binary payload → treat as MLS Welcome (existing behavior).
                                if !mls_active {
                                    match mls.join_from_welcome(&payload) {
                                        Ok(()) => {
                                            mls_active = true;
                                            println!(
                                                "\r[MLS] joined group — epoch {}",
                                                mls.epoch().unwrap_or(0)
                                            );
                                            // Derive room HPKE keypair from MLS export_secret and
                                            // publish the room public key so peers seal to us
                                            // with the epoch-bound key rather than the identity key.
                                            match mls.room_hpke_keypair() {
                                                Ok((room_sk, room_pk)) => {
                                                    room_hpke_secret = Some(room_sk);
                                                    room_hpke_pub = Some(room_pk);
                                                    let req = JsonRpcRequest::new(
                                                        next_request_id(),
                                                        rpc_methods::PUBLISH_HPKE_KEY,
                                                        PublishHpkeKeyParams { public_key: room_pk.to_vec() },
                                                    )
                                                    .unwrap();
                                                    if tx.send(req).await.is_err() {
                                                        eprintln!("connection lost.");
                                                        break;
                                                    }
                                                    tracing::debug!(
                                                        "published room HPKE key for epoch {}",
                                                        mls.epoch().unwrap_or(0)
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::warn!("failed to derive room HPKE keypair after MLS activation: {e}");
                                                }
                                            }
                                            // Re-broadcast profile now that MLS is active so it travels
                                            // encrypted.  The pre-MLS broadcast above was plaintext.
                                            if !send_profile_broadcast(&tx, &own_profile, mls_active, &mut mls).await {
                                                eprintln!("connection lost.");
                                                break;
                                            }
                                            // nie-0aj: resync in-flight sessions.
                                            if !sessions_resynced {
                                                sessions_resynced = true;
                                                if !resync_sessions(&sessions, &online, &tx, &mut mls).await {
                                                    eprintln!("connection lost.");
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => warn!("join_from_welcome: {e}"),
                                    }
                                }
                            }
                        }
                    }

                    // ---- Incoming room message ----
                    ClientEvent::Message(notif) if notif.method == rpc_methods::DELIVER => {
                        let p: nie_core::protocol::DeliverParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("failed to parse deliver params: {e}");
                                continue;
                            }
                        };
                        let from = p.from;
                        let payload = p.payload;
                        if !mls_active {
                            // Drop MLS control messages (Commit, etc.) that arrive
                            // before our Welcome.  Displaying them as raw bytes is
                            // confusing and they are not actionable without a group.
                            continue;
                        }
                        let ciphertext = match nie_core::messages::unpad(&payload) {
                            Ok(ct) => ct,
                            Err(e) => {
                                warn!("DELIVER unpad failed: {e}");
                                continue;
                            }
                        };
                        let plaintext_bytes: Vec<u8> = match mls.process_incoming(&ciphertext) {
                            Ok(Some(pt)) => pt,
                            Ok(None) => {
                                // MLS Commit — group state updated, advance epoch.
                                println!(
                                    "\r[MLS] commit applied — epoch {}",
                                    mls.epoch().unwrap_or(0)
                                );
                                continue;
                            }
                            Err(e) => {
                                warn!("MLS process_incoming: {e}");
                                continue;
                            }
                        };

                        // Dispatch on ClearMessage type.  Fall back to raw UTF-8 for
                        // messages from clients that pre-date ClearMessage serialization.
                        match serde_json::from_slice::<ClearMessage>(&plaintext_bytes) {
                            Ok(ClearMessage::Chat { text }) => {
                                let ts = Local::now().format("%H:%M");
                                // Detect IRC CTCP ACTION format: \x01ACTION text\x01
                                let formatted = if let Some(inner) = text
                                    .strip_prefix("\x01ACTION ")
                                    .and_then(|s| s.strip_suffix('\x01'))
                                {
                                    format!(
                                        "* {} {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        inner
                                    )
                                } else {
                                    format!(
                                        "{}: {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        text
                                    )
                                };
                                println!("\r[{ts}] {formatted}");
                                if let Err(e) =
                                    history.append_received(&from, text.as_bytes()).await
                                {
                                    warn!("history write failed: {e}");
                                }
                            }
                            Ok(ClearMessage::Profile { fields }) => {
                                peer_profiles.insert(from.clone(), fields);
                            }
                            Ok(ClearMessage::Ack { .. }) => {
                                // Not yet implemented — ignore.
                            }
                            Ok(ClearMessage::Payment { session_id, action }) => {
                                if !dispatch_payment(
                                    session_id,
                                    action,
                                    &from,
                                    &mut sessions,
                                    &wallet_store,
                                    wallet_fvks.as_ref(),
                                    &nicknames,
                                    &local_names,
                                    &tx,
                                    mls_active,
                                    &mut mls,
                                    send_fn_box.as_deref(),
                                    Some(&watch_registry),
                                )
                                .await
                                {
                                    eprintln!("connection lost.");
                                    break;
                                }
                            }
                            Err(_) => {
                                // Legacy raw UTF-8 from pre-ClearMessage clients.
                                let text = String::from_utf8_lossy(&plaintext_bytes);
                                let ts = Local::now().format("%H:%M");
                                let formatted = if let Some(inner) = text
                                    .strip_prefix("\x01ACTION ")
                                    .and_then(|s| s.strip_suffix('\x01'))
                                {
                                    format!(
                                        "* {} {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        inner
                                    )
                                } else {
                                    format!(
                                        "{}: {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        text
                                    )
                                };
                                println!("\r[{ts}] {formatted}");
                                if let Err(e) =
                                    history.append_received(&from, &plaintext_bytes).await
                                {
                                    warn!("history write failed: {e}");
                                }
                            }
                        }
                    }

                    // ---- Sealed broadcast received ----
                    // Sender identity is hidden inside the HPKE ciphertext; we recover
                    // it only after successful decryption.  The relay never sees `from`.
                    ClientEvent::Message(notif)
                        if notif.method == rpc_methods::SEALED_DELIVER =>
                    {
                        let params: SealedDeliverParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("malformed sealed_deliver: {e}");
                                continue;
                            }
                        };
                        // Choose the right HPKE key: room key if MLS active and derived,
                        // identity key otherwise.  Never log the secret.
                        let plaintext = {
                            let active_secret: &[u8; 32] = if mls_active {
                                match room_hpke_secret.as_ref() {
                                    Some(sk) => sk,
                                    None => {
                                        warn!("sealed_deliver while mls_active but no room_hpke_secret");
                                        continue;
                                    }
                                }
                            } else {
                                &hpke_identity_secret
                            };
                            match nie_hpke::unseal_message(active_secret, &params.sealed) {
                                Ok(pt) => pt,
                                Err(e) => {
                                    warn!("sealed_deliver unseal failed: {e}");
                                    continue;
                                }
                            }
                        };
                        // Wire format: 64 ASCII hex bytes (sender pub_id) || MLS ciphertext
                        if plaintext.len() < 64 {
                            warn!("sealed_deliver plaintext too short: {} bytes", plaintext.len());
                            continue;
                        }
                        let from = match std::str::from_utf8(&plaintext[..64]) {
                            Ok(s) => s.to_string(),
                            Err(_) => {
                                warn!("sealed_deliver: sender_pub_id not valid UTF-8");
                                continue;
                            }
                        };
                        let padded_ct = &plaintext[64..];
                        if !mls_active {
                            // Drop sealed messages that arrive before our Welcome.
                            continue;
                        }
                        // NOTE: sender_pub_id_str is asserted by the sender inside the sealed payload,
                        // not cryptographically verified. Any group member could forge this prefix.
                        // Full per-sender authentication requires a signature over the prefix — tracked
                        // in a follow-up issue.
                        let mls_ciphertext = match nie_core::messages::unpad(padded_ct) {
                            Ok(ct) => ct,
                            Err(e) => {
                                warn!("sealed_deliver unpad failed: {e}");
                                continue;
                            }
                        };
                        let plaintext_bytes: Vec<u8> = match mls.process_incoming(&mls_ciphertext) {
                            Ok(Some(pt)) => pt,
                            Ok(None) => {
                                // MLS Commit — group state updated, advance epoch.
                                println!(
                                    "\r[MLS] commit applied — epoch {}",
                                    mls.epoch().unwrap_or(0)
                                );
                                continue;
                            }
                            Err(e) => {
                                warn!("sealed_deliver MLS process_incoming: {e}");
                                continue;
                            }
                        };
                        // Dispatch on ClearMessage type — same as DELIVER handler.
                        match serde_json::from_slice::<ClearMessage>(&plaintext_bytes) {
                            Ok(ClearMessage::Chat { text }) => {
                                let ts = Local::now().format("%H:%M");
                                let formatted = if let Some(inner) = text
                                    .strip_prefix("\x01ACTION ")
                                    .and_then(|s| s.strip_suffix('\x01'))
                                {
                                    format!(
                                        "* {} {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        inner
                                    )
                                } else {
                                    format!(
                                        "{}: {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        text
                                    )
                                };
                                println!("\r[{ts}] {formatted}");
                                if let Err(e) =
                                    history.append_received(&from, text.as_bytes()).await
                                {
                                    warn!("history write failed: {e}");
                                }
                            }
                            Ok(ClearMessage::Profile { fields }) => {
                                peer_profiles.insert(from.clone(), fields);
                            }
                            Ok(ClearMessage::Ack { .. }) => {
                                // Not yet implemented — ignore.
                            }
                            Ok(ClearMessage::Payment { session_id, action }) => {
                                if !dispatch_payment(
                                    session_id,
                                    action,
                                    &from,
                                    &mut sessions,
                                    &wallet_store,
                                    wallet_fvks.as_ref(),
                                    &nicknames,
                                    &local_names,
                                    &tx,
                                    mls_active,
                                    &mut mls,
                                    send_fn_box.as_deref(),
                                    Some(&watch_registry),
                                )
                                .await
                                {
                                    eprintln!("connection lost.");
                                    break;
                                }
                            }
                            Err(_) => {
                                // Legacy raw UTF-8 from pre-ClearMessage clients.
                                let text = String::from_utf8_lossy(&plaintext_bytes);
                                let ts = Local::now().format("%H:%M");
                                let formatted = if let Some(inner) = text
                                    .strip_prefix("\x01ACTION ")
                                    .and_then(|s| s.strip_suffix('\x01'))
                                {
                                    format!(
                                        "* {} {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        inner
                                    )
                                } else {
                                    format!(
                                        "{}: {}",
                                        colored_name(&from, &nicknames, &local_names),
                                        text
                                    )
                                };
                                println!("\r[{ts}] {formatted}");
                                if let Err(e) =
                                    history.append_received(&from, &plaintext_bytes).await
                                {
                                    warn!("history write failed: {e}");
                                }
                            }
                        }
                    }

                    // ---- Sealed whisper received ----
                    // DM sealed to identity key (not room key) so it works before MLS
                    // is active (e.g., Welcome messages routed this way in the future).
                    ClientEvent::Message(notif)
                        if notif.method == rpc_methods::SEALED_WHISPER_DELIVER =>
                    {
                        let params: SealedWhisperDeliverParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("malformed sealed_whisper_deliver: {e}");
                                continue;
                            }
                        };
                        // DMs are always sealed to the identity key, not the room key.
                        // Never log hpke_identity_secret.
                        let plaintext = match nie_hpke::unseal_message(&hpke_identity_secret, &params.sealed) {
                            Ok(pt) => pt,
                            Err(e) => {
                                warn!("sealed_whisper_deliver unseal failed: {e}");
                                continue;
                            }
                        };
                        // Wire format: 64 ASCII hex bytes (sender pub_id) || payload
                        if plaintext.len() < 64 {
                            warn!("sealed_whisper_deliver plaintext too short: {} bytes", plaintext.len());
                            continue;
                        }
                        let from = match std::str::from_utf8(&plaintext[..64]) {
                            Ok(s) => s.to_string(),
                            Err(_) => {
                                warn!("sealed_whisper_deliver: sender_pub_id not valid UTF-8");
                                continue;
                            }
                        };
                        let inner_payload = &plaintext[64..];
                        if mls_active {
                            match mls.process_incoming(inner_payload) {
                                Ok(Some(pt)) => {
                                    match serde_json::from_slice::<ClearMessage>(&pt) {
                                        Ok(ClearMessage::Chat { text }) => {
                                            let ts = Local::now().format("%H:%M");
                                            let formatted = format!(
                                                "(dm) {}: {}",
                                                colored_name(&from, &nicknames, &local_names),
                                                text
                                            );
                                            println!("\r[{ts}] {formatted}");
                                            if let Err(e) =
                                                history.append_received(&from, text.as_bytes()).await
                                            {
                                                warn!("history write failed: {e}");
                                            }
                                        }
                                        Ok(_) => {
                                            tracing::debug!("sealed_whisper_deliver: non-chat ClearMessage from {from}");
                                        }
                                        Err(e) => {
                                            warn!("sealed_whisper_deliver ClearMessage parse: {e}");
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // MLS non-application message (e.g. proposal) — process silently.
                                    tracing::debug!("sealed_whisper_deliver: MLS non-application message from {from}");
                                }
                                Err(e) => {
                                    warn!("sealed_whisper_deliver MLS process_incoming: {e}");
                                }
                            }
                        } else {
                            // Not yet in MLS group — treat inner_payload as a raw MLS Welcome
                            // (same as WhisperDeliver before MLS is active).
                            match mls.join_from_welcome(inner_payload) {
                                Ok(()) => {
                                    mls_active = true;
                                    println!(
                                        "\r[MLS] joined group (sealed welcome) — epoch {}",
                                        mls.epoch().unwrap_or(0)
                                    );
                                    match mls.room_hpke_keypair() {
                                        Ok((room_sk, room_pk)) => {
                                            room_hpke_secret = Some(room_sk);
                                            room_hpke_pub = Some(room_pk);
                                            let req = JsonRpcRequest::new(
                                                next_request_id(),
                                                rpc_methods::PUBLISH_HPKE_KEY,
                                                PublishHpkeKeyParams { public_key: room_pk.to_vec() },
                                            )
                                            .unwrap();
                                            if tx.send(req).await.is_err() {
                                                eprintln!("connection lost.");
                                                break;
                                            }
                                            tracing::debug!(
                                                "published room HPKE key for epoch {}",
                                                mls.epoch().unwrap_or(0)
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!("failed to derive room HPKE keypair: {e}");
                                        }
                                    }
                                    if !send_profile_broadcast(&tx, &own_profile, mls_active, &mut mls).await {
                                        eprintln!("connection lost.");
                                        break;
                                    }
                                    if !sessions_resynced {
                                        sessions_resynced = true;
                                        if !resync_sessions(&sessions, &online, &tx, &mut mls).await {
                                            eprintln!("connection lost.");
                                            break;
                                        }
                                    }
                                }
                                Err(e) => warn!("sealed_whisper_deliver join_from_welcome: {e}"),
                            }
                        }
                    }

                    // ---- Nickname events ----
                    ClientEvent::Message(notif) if notif.method == rpc_methods::USER_NICKNAME => {
                        let p: nie_core::protocol::UserNicknameParams =
                            match serde_json::from_value(
                                notif.params.unwrap_or(serde_json::Value::Null),
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!("failed to parse user_nickname params: {e}");
                                    continue;
                                }
                            };
                        let pub_id = p.pub_id;
                        let nickname = p.nickname;
                        let old = colored_name(&pub_id, &nicknames, &local_names);
                        nicknames.insert(pub_id.clone(), nickname.clone());
                        let marker = if pub_id == my_pub_id { " (you)" } else { "" };
                        println!("\r[~] {old} is now known as \"{nickname}\"{marker}");
                    }

                    // ---- Subscription activated notification ----
                    ClientEvent::Message(notif)
                        if notif.method == rpc_methods::SUBSCRIPTION_ACTIVE =>
                    {
                        let params: SubscriptionActiveParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("malformed subscription_active: {e}");
                                continue;
                            }
                        };
                        println!("[subscription] Active — expires {}", params.expires);
                    }

                    // ---- Group message ----
                    ClientEvent::Message(notif)
                        if notif.method == rpc_methods::GROUP_DELIVER =>
                    {
                        let params: GroupDeliverParams = match serde_json::from_value(
                            notif.params.unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("malformed group_deliver: {e}");
                                continue;
                            }
                        };
                        let gid = params.group_id.clone();
                        let group_name = match active_groups.get(&gid) {
                            Some(gs) => gs.name.clone(),
                            None => {
                                warn!("group_deliver for unknown group {gid}; ignoring");
                                continue;
                            }
                        };
                        let payload = params.payload;
                        // Attempt MLS decrypt if we have a group context for this id.
                        let plaintext = if mls.has_group_id(gid.as_bytes()) {
                            match mls.process_for_group(gid.as_bytes(), &payload) {
                                Ok(Some(pt)) => pt,
                                // Commit or other non-application message — no display.
                                Ok(None) => continue,
                                Err(e) => {
                                    warn!("MLS decrypt failed for group {gid}: {e}");
                                    continue;
                                }
                            }
                        } else {
                            payload
                        };
                        match serde_json::from_slice::<ClearMessage>(&plaintext) {
                            Ok(ClearMessage::Chat { text }) => {
                                let sender =
                                    colored_name(&params.from, &nicknames, &local_names);
                                println!("\r[{group_name}] {sender}: {text}");
                            }
                            Ok(_) | Err(_) => {
                                warn!("group_deliver: unrecognized message format for group {gid}");
                            }
                        }
                    }

                    ClientEvent::Message(other) => info!("relay: {other:?}"),
                }
            }

            // ---- Stdin (rustyline) ----
            line_opt = line_rx.recv() => {
                let Some(line) = line_opt else { break };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }

                // /iam <nickname>
                if let Some(rest) = line.strip_prefix("/iam ") {
                    let nickname = rest.trim().to_string();
                    let req = JsonRpcRequest::new(
                        next_request_id(),
                        rpc_methods::SET_NICKNAME,
                        SetNicknameParams { nickname },
                    )
                    .unwrap();
                    if tx.send(req).await.is_err() {
                        eprintln!("connection lost.");
                        break;
                    }
                    continue;
                }

                // /who — print current online list
                if line == "/who" {
                    if online.is_empty() {
                        println!("(nobody online)");
                    } else {
                        for pub_id in &online {
                            let marker = if *pub_id == my_pub_id { " (you)" } else { "" };
                            println!("  {}{}", display_name(pub_id, &nicknames, &local_names), marker);
                        }
                    }
                    continue;
                }

                // /set <key> <value> — set a profile field and rebroadcast
                if let Some(rest) = line.strip_prefix("/set ") {
                    let mut parts = rest.trim().splitn(2, ' ');
                    match (parts.next(), parts.next()) {
                        (Some(key), Some(value)) => {
                            own_profile.insert(key.to_string(), value.to_string());
                            match crate::profile::validate(&own_profile) {
                                Ok(()) => {
                                    crate::profile::save(data_dir, &own_profile);
                                    if !send_profile_broadcast(
                                        &tx,
                                        &own_profile,
                                        mls_active,
                                        &mut mls,
                                    )
                                    .await
                                    {
                                        eprintln!("connection lost.");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    // Roll back the insertion so own_profile stays valid.
                                    own_profile.remove(key);
                                    println!("profile error: {e}");
                                }
                            }
                        }
                        _ => println!("usage: /set <key> <value>"),
                    }
                    continue;
                }

                // /unset <key> — remove a profile field and rebroadcast
                if let Some(rest) = line.strip_prefix("/unset ") {
                    let key = rest.trim();
                    if own_profile.remove(key).is_none() {
                        println!("{key:?} is not set");
                    } else {
                        crate::profile::save(data_dir, &own_profile);
                        if !send_profile_broadcast(&tx, &own_profile, mls_active, &mut mls).await {
                            eprintln!("connection lost.");
                            break;
                        }
                    }
                    continue;
                }

                // /profile [handle] — display own or a peer's profile
                if line == "/profile" || line.starts_with("/profile ") {
                    let target = line.strip_prefix("/profile ").map(str::trim);
                    match target {
                        None | Some("") => {
                            // Own profile.
                            if own_profile.is_empty() {
                                println!("(no profile set — use /set <key> <value>)");
                            } else {
                                let mut pairs: Vec<_> = own_profile.iter().collect();
                                pairs.sort_by_key(|(k, _)| k.as_str());
                                for (k, v) in pairs {
                                    println!("  {k}: {v}");
                                }
                            }
                        }
                        Some(handle) => {
                            // Find the peer by handle or pub_id prefix.
                            let peer_id = online.iter().find(|id| {
                                display_name(id, &nicknames, &local_names)
                                    .to_lowercase()
                                    .contains(&handle.to_lowercase())
                                    || id.starts_with(handle)
                            });
                            match peer_id.and_then(|id| peer_profiles.get(id.as_str())) {
                                Some(fields) if !fields.is_empty() => {
                                    let mut pairs: Vec<_> = fields.iter().collect();
                                    pairs.sort_by_key(|(k, _)| k.as_str());
                                    for (k, v) in pairs {
                                        println!("  {k}: {v}");
                                    }
                                }
                                Some(_) | None => {
                                    println!("(no profile received from {handle})");
                                }
                            }
                        }
                    }
                    continue;
                }

                // /me <action> — send as IRC CTCP ACTION
                if let Some(rest) = line.strip_prefix("/me ") {
                    let rest = rest.trim();
                    let my_name = display_name(&my_pub_id, &nicknames, &local_names);
                    println!("\r* {my_name} {rest}");
                    let action_text = format!("\x01ACTION {rest}\x01");
                    // serde_json::to_vec on derived Serialize cannot fail
                    let line_bytes =
                        serde_json::to_vec(&ClearMessage::Chat { text: action_text.clone() })
                            .unwrap();
                    let payload: Vec<u8> = if mls_active {
                        match mls.encrypt(&line_bytes) {
                            Ok(ct) => match nie_core::messages::pad(&ct) {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("\r[error] cannot send: payload padding failed ({e}).");
                                    continue;
                                }
                            },
                            Err(e) => {
                                eprintln!("\r[error] cannot send: MLS encryption failed ({e}). Reconnect to reset MLS state.");
                                continue;
                            }
                        }
                    } else {
                        line_bytes.clone()
                    };
                    // Store the human-readable CTCP text in history, not the JSON wrapper.
                    if let Err(e) = history.append_sent(&my_pub_id, action_text.as_bytes()).await {
                        warn!("history write failed: {e}");
                    }
                    let req = JsonRpcRequest::new(
                        next_request_id(),
                        rpc_methods::BROADCAST,
                        BroadcastParams { payload },
                    )
                    .unwrap();
                    if tx.send(req).await.is_err() {
                        eprintln!("connection lost.");
                        break;
                    }
                    continue;
                }

                // /cat <path> — read file and send contents
                if let Some(path_str) = line.strip_prefix("/cat ") {
                    let path_str = path_str.trim();
                    match tokio::fs::read(path_str).await {
                        Err(e) => { println!("cannot read {path_str}: {e}"); }
                        Ok(bytes) if bytes.len() > 4096 => {
                            println!("file too large ({}B > 4KB limit)", bytes.len());
                        }
                        Ok(bytes) => {
                            match String::from_utf8(bytes) {
                                Err(_) => { println!("binary file — only text can be sent"); }
                                Ok(text) => {
                                    let content_len = text.len();
                                    // serde_json::to_vec on derived Serialize cannot fail
                                    let line_bytes = serde_json::to_vec(&ClearMessage::Chat { text }).unwrap();
                                    let payload: Vec<u8> = if mls_active {
                                        match mls.encrypt(&line_bytes) {
                                            Ok(ct) => match nie_core::messages::pad(&ct) {
                                                Ok(p) => p,
                                                Err(e) => {
                                                    eprintln!("\r[error] cannot send: payload padding failed ({e}).");
                                                    continue;
                                                }
                                            },
                                            Err(e) => {
                                                eprintln!("\r[error] cannot send: MLS encryption failed ({e}). Reconnect to reset MLS state.");
                                                continue;
                                            }
                                        }
                                    } else {
                                        line_bytes.clone()
                                    };
                                    println!("\r(sent {} bytes from {path_str})", content_len);
                                    if let Err(e) = history.append_sent(&my_pub_id, &line_bytes).await {
                                        warn!("history write failed: {e}");
                                    }
                                    let req = JsonRpcRequest::new(
                                        next_request_id(),
                                        rpc_methods::BROADCAST,
                                        BroadcastParams { payload },
                                    )
                                    .unwrap();
                                    if tx.send(req).await.is_err() {
                                        eprintln!("connection lost.");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                // /! <cmd> — run a command and send stdout.
                // Uses word-splitting (shlex) instead of sh -c so shell metacharacters
                // (|, ;, $(), &&, >) are not interpreted.  "/! echo foo" runs
                // Command::new("echo").arg("foo"), not a shell expression.
                if let Some(cmd_str) = line.strip_prefix("/! ") {
                    let cmd_str = cmd_str.trim();
                    let argv = match shlex::split(cmd_str) {
                        Some(v) if !v.is_empty() => v,
                        _ => {
                            println!("usage: /! <command> [args...]");
                            continue;
                        }
                    };
                    match tokio::process::Command::new(&argv[0])
                        .args(&argv[1..])
                        .output()
                        .await
                    {
                        Err(e) => { println!("failed to run command: {e}"); }
                        Ok(out) => {
                            let mut stdout = out.stdout;
                            let truncated = stdout.len() > 4096;
                            stdout.truncate(4096);
                            let text = String::from_utf8_lossy(&stdout).into_owned();
                            let display = if truncated {
                                format!("{}\n[... truncated to 4KB]", text.trim_end())
                            } else {
                                text.trim_end().to_string()
                            };
                            if display.is_empty() {
                                println!("(command produced no output)");
                            } else {
                                let content_len = display.len();
                                // serde_json::to_vec on derived Serialize cannot fail
                                let line_bytes = serde_json::to_vec(&ClearMessage::Chat { text: display }).unwrap();
                                let payload: Vec<u8> = if mls_active {
                                    match mls.encrypt(&line_bytes) {
                                        Ok(ct) => match nie_core::messages::pad(&ct) {
                                            Ok(p) => p,
                                            Err(e) => {
                                                eprintln!("\r[error] cannot send: payload padding failed ({e}).");
                                                continue;
                                            }
                                        },
                                        Err(e) => {
                                            eprintln!("\r[error] cannot send: MLS encryption failed ({e}). Reconnect to reset MLS state.");
                                            continue;
                                        }
                                    }
                                } else {
                                    line_bytes.clone()
                                };
                                println!("\r(sent {} bytes of output)", content_len);
                                if let Err(e) = history.append_sent(&my_pub_id, &line_bytes).await {
                                    warn!("history write failed: {e}");
                                }
                                let req = JsonRpcRequest::new(
                                    next_request_id(),
                                    rpc_methods::BROADCAST,
                                    BroadcastParams { payload },
                                )
                                .unwrap();
                                if tx.send(req).await.is_err() {
                                    eprintln!("connection lost.");
                                    break;
                                }
                            }
                        }
                    }
                    continue;
                }

                // /alias <name> <pubid> — save a local display name for a peer
                if let Some(rest) = line.strip_prefix("/alias ") {
                    let mut parts = rest.splitn(2, ' ');
                    let name = parts.next().unwrap_or("").trim().to_string();
                    let pubkey = parts.next().unwrap_or("").trim().to_string();
                    if name.is_empty() || pubkey.is_empty() {
                        println!("usage: /alias <name> <pubid>");
                    } else {
                        contacts.add(name.clone(), pubkey.clone());
                        match contacts.save(data_dir) {
                            Ok(()) => {
                                local_names.insert(pubkey, name.clone());
                                println!("alias saved: {name}");
                            }
                            Err(e) => eprintln!("failed to save contacts: {e}"),
                        }
                    }
                    continue;
                }

                // /dm <handle> <text> — send a private whisper to one peer
                if let Some(rest) = line.strip_prefix("/dm ") {
                    let rest = rest.trim();
                    let mut parts = rest.splitn(2, ' ');
                    let handle = parts.next().unwrap_or("").trim();
                    let text = parts.next().unwrap_or("").trim();
                    if handle.is_empty() || text.is_empty() {
                        println!("usage: /dm <handle> <text>");
                        continue;
                    }
                    let peer = match resolve_handle(handle, &online, &nicknames, &local_names) {
                        Ok(id) => id,
                        Err(_) => {
                            println!("[dm] unknown: {handle}");
                            continue;
                        }
                    };
                    // Phase 1 (pre-MLS): DMs are plaintext ClearMessage::Chat in Whisper payload.
                    // serde_json::to_vec on derived Serialize with only String fields cannot fail
                    let payload =
                        serde_json::to_vec(&ClearMessage::Chat { text: text.to_string() })
                            .unwrap();
                    let req = JsonRpcRequest::new(
                        next_request_id(),
                        rpc_methods::WHISPER,
                        WhisperParams { to: peer.clone(), payload },
                    )?;
                    tx.send(req).await?;
                    let ts = Local::now().format("%H:%M");
                    println!(
                        "\r[{ts}] DM → {}: {}",
                        display_name(&peer, &nicknames, &local_names),
                        text
                    );
                    continue;
                }

                // /confirm <short_id> — payer confirms payment sent (nie-c20)
                // Finds the payer session whose UUID starts with short_id, sends
                // PaymentAction::Sent with a stub tx_hash, transitions state to Sent.
                if let Some(rest) = line.strip_prefix("/confirm ") {
                    let short_id = rest.trim();
                    // Find the matching session: role=Payer, state=AddressProvided,
                    // UUID prefix matches short_id.
                    let found = sessions.iter().find(|(id, s)| {
                        s.role == PaymentRole::Payer
                            && s.state == PaymentState::AddressProvided
                            && id.to_string().starts_with(short_id)
                    });
                    match found {
                        None => {
                            println!(
                                "[pay] no payer session with id starting '{short_id}' \
                                 in AddressProvided state"
                            );
                        }
                        Some((&found_id, found_session)) => {
                            let chain = found_session.chain;
                            let amount_zatoshi = found_session.amount_zatoshi;
                            let stub_hash = format!("stub-{}", Uuid::new_v4());
                            if !send_payment_message(
                                found_id,
                                PaymentAction::Sent {
                                    chain,
                                    tx_hash: stub_hash.clone(),
                                    amount_zatoshi,
                                },
                                &tx,
                                mls_active,
                                &mut mls,
                            )
                            .await
                            {
                                eprintln!("connection lost.");
                                break;
                            }
                            // Transition to Sent and persist.
                            let session = sessions.get_mut(&found_id).unwrap();
                            session.state = PaymentState::Sent;
                            session.tx_hash = Some(stub_hash);
                            session.updated_at = chrono::Utc::now().timestamp();
                            if let Err(e) = wallet_store.upsert_session(session).await {
                                warn!("failed to persist payer Sent for {found_id}: {e}");
                            }
                            println!("[pay] Sent (stub tx). Waiting for confirmation.");
                        }
                    }
                    continue;
                }

                // /cancel <short_id> — cancel an in-flight payment session (nie-0bj)
                // Sends PaymentAction::Cancelled to the peer and transitions local state
                // to Expired.  Accepts any non-terminal session whose UUID starts with
                // short_id.
                if let Some(rest) = line.strip_prefix("/cancel ") {
                    let short_id = rest.trim();
                    let found = sessions.iter().find(|(id, s)| {
                        !matches!(
                            s.state,
                            PaymentState::Confirmed | PaymentState::Failed | PaymentState::Expired
                        ) && id.to_string().starts_with(short_id)
                    });
                    match found {
                        None => {
                            println!(
                                "[pay] no active session with id starting '{short_id}'"
                            );
                        }
                        Some((&found_id, _)) => {
                            // Persist Expired BEFORE sending Cancelled so that if the
                            // channel is already closed (send_payment_message returns
                            // false → break), the local state is already consistent.
                            // The peer either received Cancelled or will time out via
                            // the 24-hour expiry check on their next reconnect.
                            let session = sessions.get_mut(&found_id).unwrap();
                            session.state = PaymentState::Expired;
                            session.updated_at = chrono::Utc::now().timestamp();
                            if let Err(e) = wallet_store.upsert_session(session).await {
                                warn!(
                                    "failed to persist cancelled session {found_id}: {e}"
                                );
                            }
                            if !send_payment_message(
                                found_id,
                                PaymentAction::Cancelled {
                                    reason: "payer cancelled".to_string(),
                                },
                                &tx,
                                mls_active,
                                &mut mls,
                            )
                            .await
                            {
                                eprintln!("connection lost.");
                                break;
                            }
                            println!("[pay] session {} cancelled.", &found_id.to_string()[..8]);
                        }
                    }
                    continue;
                }

                // /pay <handle> <amount> [zcash|monero|mobilecoin]
                // Initiates a payment session: creates a payer PaymentSession and broadcasts
                // PaymentAction::Request so the payee can respond with an address.
                if let Some(rest) = line.strip_prefix("/pay ") {
                    if wallet_fvks.is_none() {
                        println!("[pay] No wallet. Run `nie wallet init` first.");
                        continue;
                    }
                    let parts: Vec<&str> = rest.trim().splitn(3, ' ').collect();
                    let (handle, amount_str, chain_str) = match parts.as_slice() {
                        [h, a] => (*h, *a, "zcash"),
                        [h, a, c] => (*h, *a, *c),
                        _ => {
                            println!("usage: /pay <handle> <amount> [zcash|monero|mobilecoin]");
                            continue;
                        }
                    };
                    let chain = match chain_str {
                        "zcash" => Chain::Zcash,
                        "monero" => Chain::Monero,
                        "mobilecoin" => Chain::Mobilecoin,
                        other => {
                            println!("[pay] unknown chain '{other}'. Supported: zcash, monero, mobilecoin");
                            continue;
                        }
                    };
                    let peer_pub_id =
                        match resolve_handle(handle, &online, &nicknames, &local_names) {
                            Ok(id) => id,
                            Err(e) => {
                                println!("[pay] {e}");
                                continue;
                            }
                        };
                    let amount_zatoshi = match parse_zec_to_zatoshi(amount_str) {
                        Ok(v) => v,
                        Err(e) => {
                            println!("[pay] {e}");
                            continue;
                        }
                    };
                    if amount_zatoshi < DUST_THRESHOLD {
                        println!(
                            "[pay] amount must be at least {DUST_THRESHOLD} zatoshi \
                             ({} ZEC)",
                            zatoshi_to_zec_string(DUST_THRESHOLD)
                        );
                        continue;
                    }
                    let estimated_fee = zip317_fee(sapling_logical_actions(1, 2));
                    println!(
                        "[pay] Estimated fee: {estimated_fee} zatoshi ({:.4} ZEC) — actual may vary by note count",
                        estimated_fee as f64 / 1e8
                    );
                    let now = chrono::Utc::now().timestamp();
                    let session_id = Uuid::new_v4();
                    let payer_session = PaymentSession {
                        id: session_id,
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
                    if let Err(e) = wallet_store.upsert_session(&payer_session).await {
                        warn!("failed to persist payer session {session_id}: {e}");
                    }
                    sessions.insert(session_id, payer_session);
                    let short_id = &session_id.to_string()[..8];
                    println!(
                        "[pay] requesting {amount_zatoshi} zatoshi on {chain_str} → {} (session {short_id})",
                        display_name(&peer_pub_id, &nicknames, &local_names)
                    );
                    // Payment negotiation is broadcast to the MLS group, so all
                    // room members can see the amount and address.  This is an
                    // architectural constraint of the broadcast-only relay.
                    println!("[pay] Note: payment details are visible to all room members.");
                    if !send_payment_message(
                        session_id,
                        PaymentAction::Request {
                            chain,
                            amount_zatoshi,
                        },
                        &tx,
                        mls_active,
                        &mut mls,
                    )
                    .await
                    {
                        eprintln!("connection lost.");
                        break;
                    }
                    continue;
                }

                // /balance — show shielded ZEC balance
                if line == "/balance" {
                    if wallet_fvks.is_none() {
                        println!("[wallet] No wallet. Run `nie wallet init` first.");
                    } else {
                        match wallet_store.scan_tip().await {
                            Err(e) => println!("[wallet] error reading wallet: {e}"),
                            Ok(scan_tip) => {
                                match wallet_store.balance(scan_tip, 10).await {
                                    Err(e) => println!("[wallet] error reading balance: {e}"),
                                    Ok(bal) => {
                                        println!(
                                            "[wallet] confirmed {} ZEC | pending {} ZEC | \
                                             synced to block {scan_tip}",
                                            zatoshi_to_zec_string(bal.confirmed_zatoshi),
                                            zatoshi_to_zec_string(bal.pending_zatoshi),
                                        );
                                        if scan_tip == 0 {
                                            println!(
                                                "[wallet] Wallet has not synced yet. \
                                                 Run `nie wallet sync` to scan the blockchain."
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                // /receive — show Unified Address for receiving ZEC
                if line == "/receive" {
                    match &wallet_fvks {
                        None => println!("[wallet] No wallet. Run `nie wallet init` first."),
                        Some(fvks) => {
                            let di = match wallet_store
                                .get_diversifier_index(PAYMENT_ACCOUNT)
                                .await
                            {
                                Ok(idx) => idx,
                                Err(e) => {
                                    println!("[wallet] error reading diversifier index: {e}");
                                    continue;
                                }
                            };
                            match diversified_address(
                                &fvks.sapling,
                                &fvks.orchard,
                                di,
                                fvks.network,
                            ) {
                                Err(e) => println!("[wallet] address generation failed: {e}"),
                                Ok((_, addr)) => {
                                    println!("[receive] Your Unified Address:");
                                    println!("{addr}");
                                    println!(
                                        "[receive] Sharing this address links all payments \
                                         to the same identity. For unlinkable receipts, ask \
                                         payers to type `/pay <your-handle> <amount>` — that \
                                         generates a fresh address per session."
                                    );
                                    if let Ok(scan_tip) = wallet_store.scan_tip().await {
                                        if scan_tip == 0 {
                                            println!(
                                                "[receive] Wallet has not synced yet. \
                                                 Run `nie wallet sync` before sharing this address \
                                                 so incoming payments are visible."
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                // /payments — show payment session history
                if line == "/payments" {
                    match wallet_store.all_sessions().await {
                        Err(e) => println!("[payments] error: {e}"),
                        Ok(mut history) => {
                            if history.is_empty() {
                                println!("[payments] No payment sessions.");
                            } else {
                                // Most-recent first.
                                history.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                                for s in &history {
                                    let dir = match s.role {
                                        PaymentRole::Payer => "→",
                                        PaymentRole::Payee => "←",
                                    };
                                    let status = match s.state {
                                        PaymentState::Requested => "pending",
                                        PaymentState::AddressProvided => "pending",
                                        PaymentState::Sent => "sent",
                                        PaymentState::Confirmed => "complete",
                                        PaymentState::Failed => "failed",
                                        PaymentState::Expired => "expired",
                                    };
                                    let short = &s.id.to_string()[..8];
                                    let peer =
                                        display_name(&s.peer_pub_id, &nicknames, &local_names);
                                    println!(
                                        "[{short}] {dir} {peer}  {} ZEC  {status}",
                                        zatoshi_to_zec_string(s.amount_zatoshi)
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }

                // /subscribe [<days>] — request a subscription invoice from the relay
                // Bare /subscribe defaults to 30 days.
                if line == "/subscribe" || line.starts_with("/subscribe ") {
                    let days: u32 = if line == "/subscribe" {
                        30
                    } else {
                        let rest = line.strip_prefix("/subscribe ").unwrap_or("").trim();
                        match rest.parse::<u32>() {
                            Ok(d) if d > 0 => d,
                            _ => {
                                println!("usage: /subscribe <days>  (e.g., /subscribe 30)");
                                continue;
                            }
                        }
                    };
                    let req = JsonRpcRequest::new(
                        next_request_id(),
                        rpc_methods::SUBSCRIBE_REQUEST,
                        SubscribeRequestParams { duration_days: days },
                    )
                    .unwrap();
                    if tx.send(req).await.is_err() {
                        eprintln!("connection lost.");
                        break;
                    }
                    // Response is async — handled in ClientEvent::Response match arm.
                    continue;
                }

                // /group <subcommand>
                if line == "/group" || line.starts_with("/group ") {
                    let rest = line.strip_prefix("/group").unwrap_or("").trim();
                    if let Some(name) = rest.strip_prefix("create ") {
                        let name = name.trim().to_string();
                        if name.is_empty() {
                            println!("usage: /group create <name>");
                        } else {
                            let req = JsonRpcRequest::new(
                                next_request_id(),
                                rpc_methods::GROUP_CREATE,
                                GroupCreateParams { name },
                            )
                            .unwrap();
                            if tx.send(req).await.is_err() {
                                eprintln!("connection lost.");
                                break;
                            }
                            // Response handled in ClientEvent::Response (GroupCreateResult).
                        }
                        continue;
                    }
                    if rest == "list" {
                        let req = JsonRpcRequest::new(
                            next_request_id(),
                            rpc_methods::GROUP_LIST,
                            serde_json::json!({}),
                        )
                        .unwrap();
                        if tx.send(req).await.is_err() {
                            eprintln!("connection lost.");
                            break;
                        }
                        // Response handled in ClientEvent::Response (GroupListResult).
                        continue;
                    }
                    if let Some(name) = rest.strip_prefix("leave ") {
                        let name = name.trim();
                        // Resolve name to group_id (case-insensitive match on group name).
                        let found = active_groups.iter().find(|(_, gs)| {
                            gs.name.eq_ignore_ascii_case(name)
                        });
                        match found {
                            None => {
                                println!("[group] Unknown group '{name}'. Use /group list to see your groups.");
                            }
                            Some((gid, gs)) => {
                                let gid = gid.clone();
                                let gname = gs.name.clone();
                                let req = JsonRpcRequest::new(
                                    next_request_id(),
                                    rpc_methods::GROUP_LEAVE,
                                    GroupLeaveParams { group_id: gid.clone() },
                                )
                                .unwrap();
                                if tx.send(req).await.is_err() {
                                    eprintln!("connection lost.");
                                    break;
                                }
                                // Optimistic update: remove immediately.
                                active_groups.remove(&gid);
                                println!("[group] Left '{gname}'");
                            }
                        }
                        continue;
                    }
                    if let Some(rest2) = rest.strip_prefix("send ") {
                        // /group send <name> <text>
                        let (name, text) = match rest2.split_once(' ') {
                            Some((n, t)) => (n.trim(), t.trim()),
                            None => {
                                println!("usage: /group send <name> <text>");
                                continue;
                            }
                        };
                        if text.is_empty() {
                            println!("usage: /group send <name> <text>");
                            continue;
                        }
                        let found = active_groups
                            .iter()
                            .find(|(_, gs)| gs.name.eq_ignore_ascii_case(name));
                        match found {
                            None => {
                                println!(
                                    "[group] Unknown group '{name}'. \
                                     Use /group list to see your groups."
                                );
                            }
                            Some((gid, gs)) => {
                                let gid = gid.clone();
                                let gname = gs.name.clone();
                                // serde_json::to_vec on a derived Serialize cannot fail
                                let clear_bytes = serde_json::to_vec(&ClearMessage::Chat {
                                    text: text.to_string(),
                                })
                                .unwrap();
                                let payload = if mls.has_group_id(gid.as_bytes()) {
                                    match mls.encrypt_for_group(gid.as_bytes(), &clear_bytes) {
                                        Ok(ct) => ct,
                                        Err(e) => {
                                            eprintln!(
                                                "[group] MLS encrypt failed for '{gname}': {e}"
                                            );
                                            continue;
                                        }
                                    }
                                } else {
                                    clear_bytes
                                };
                                let req = JsonRpcRequest::new(
                                    next_request_id(),
                                    rpc_methods::GROUP_SEND,
                                    GroupSendParams { group_id: gid, payload },
                                )
                                .unwrap();
                                if tx.send(req).await.is_err() {
                                    eprintln!("connection lost.");
                                    break;
                                }
                                println!("[{gname}] you: {text}");
                            }
                        }
                        continue;
                    }
                    // Bare /group or unrecognized subcommand.
                    println!(
                        "usage:\n\
                         /group create <name>  — create a new group channel\n\
                         /group list           — list your groups\n\
                         /group leave <name>   — leave a group\n\
                         /group send <name> <text>  — send message to a group"
                    );
                    continue;
                }

                // /clear — clear terminal
                if line == "/clear" {
                    print!("\x1b[2J\x1b[H");
                    let _ = std::io::stdout().flush();
                    continue;
                }

                if let Some(reply) = handle_slash(&line) {
                    println!("{reply}");
                    if line == "/quit" || line == "/q" {
                        break;
                    }
                    continue;
                }

                // Wrap text in ClearMessage::Chat, then encrypt with MLS if active.
                // serde_json::to_vec on derived Serialize cannot fail
                let line_bytes =
                    serde_json::to_vec(&ClearMessage::Chat { text: line.clone() }).unwrap();

                // Store the human-readable text in history, not the JSON wrapper.
                if let Err(e) = history.append_sent(&my_pub_id, line.as_bytes()).await {
                    warn!("history write failed: {e}");
                }

                if mls_active {
                    let mls_ciphertext = match mls.encrypt(&line_bytes) {
                        Ok(ct) => match nie_core::messages::pad(&ct) {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("\r[error] cannot send: payload padding failed ({e}).");
                                continue;
                            }
                        },
                        Err(e) => {
                            eprintln!("\r[error] cannot send: MLS encryption failed ({e}). Reconnect to reset MLS state.");
                            continue;
                        }
                    };
                    if let Some(pub_key) = room_hpke_pub {
                        // Sealed broadcast: sender_pub_id (64 ASCII bytes) || MLS ciphertext,
                        // HPKE-sealed to the room public key so relay cannot identify sender.
                        let mut sealed_plaintext = Vec::with_capacity(64 + mls_ciphertext.len());
                        sealed_plaintext.extend_from_slice(my_pub_id.as_bytes());
                        sealed_plaintext.extend_from_slice(&mls_ciphertext);
                        match nie_hpke::seal_message(&pub_key, &sealed_plaintext) {
                            Ok(sealed) => {
                                let req = JsonRpcRequest::new(
                                    next_request_id(),
                                    rpc_methods::SEALED_BROADCAST,
                                    SealedBroadcastParams { sealed },
                                )
                                .unwrap();
                                if tx.send(req).await.is_err() {
                                    eprintln!("connection lost.");
                                    break;
                                }
                            }
                            Err(e) => {
                                // seal_message should not fail for valid keys; log and drop.
                                tracing::warn!("HPKE seal failed, dropping message: {e}");
                            }
                        }
                    } else {
                        // MLS is active but room HPKE key is missing (derive failed at activation).
                        // Do NOT fall back to identified broadcast — that would expose the sender to the relay.
                        tracing::warn!("sealed send skipped: MLS active but room HPKE key not yet available");
                        eprintln!("\r[warn] message not sent: sealed channel not ready yet, try again");
                    }
                } else {
                    // fallback: MLS not yet active — send plaintext broadcast (pre-MLS compat)
                    let req = JsonRpcRequest::new(
                        next_request_id(),
                        rpc_methods::BROADCAST,
                        BroadcastParams { payload: line_bytes },
                    )
                    .unwrap();
                    if tx.send(req).await.is_err() {
                        eprintln!("connection lost.");
                        break;
                    }
                }
            }

            // ---- Confirmation watcher ----
            event = conf_rx.recv() => {
                let Some(ev) = event else {
                    // Watcher exited cleanly; loop continues without a watcher.
                    continue;
                };
                // Validate txid: must be exactly 64 lowercase hex chars.
                if ev.txid.len() != 64 || !ev.txid.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()) {
                    warn!("watcher sent malformed txid '{}'; ignoring", ev.txid);
                    continue;
                }
                if let Some(session) = sessions.get_mut(&ev.session_id) {
                    // Accept both Sent and AddressProvided: the watcher may fire
                    // before the relay delivers PaymentAction::Sent to the payee.
                    let watchable = session.role == PaymentRole::Payee
                        && (session.state == PaymentState::Sent
                            || session.state == PaymentState::AddressProvided);
                    if watchable {
                        let addr_key = session.address.clone();
                        info!("Payment confirmed: session={} txid={}", ev.session_id, ev.txid);
                        session.state = PaymentState::Confirmed;
                        session.tx_hash = Some(ev.txid.clone());
                        session.updated_at = chrono::Utc::now().timestamp();
                        if let Err(e) = wallet_store.upsert_session(session).await {
                            warn!("failed to persist Confirmed for session {}: {e}", ev.session_id);
                        }
                        // Deregister the address so the watcher stops watching it.
                        if let Some(ua_str) = addr_key {
                            if let Ok((_net, ua)) = decode_unified_address(&ua_str) {
                                if let Some(sapling_bytes) = sapling_receiver(&ua) {
                                    let key: String =
                                        sapling_bytes.iter().map(|b| format!("{b:02x}")).collect();
                                    watch_registry.deregister(&key);
                                }
                            }
                        }
                        println!("\r[pay] Payment confirmed on-chain (tx {}). Session complete.", &ev.txid[..16]);
                        let _ = send_payment_message(
                            ev.session_id,
                            PaymentAction::Confirmed { tx_hash: ev.txid.clone() },
                            &tx,
                            mls_active,
                            &mut mls,
                        )
                        .await;
                        // Peer being disconnected is fine; Confirmed is best-effort.
                    } else {
                        warn!(
                            "ConfirmationEvent for session {} but role={:?} state={:?}; ignoring",
                            ev.session_id, session.role, session.state
                        );
                    }
                } else {
                    warn!("ConfirmationEvent for unknown session {}; ignoring", ev.session_id);
                }
            }

            // ---- Ctrl-C ----
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }

    // Signal the block watcher task to stop and wait for it to finish.
    let _ = shutdown_tx.send(true);
    if let Some(handle) = _watcher_handle {
        let _ = handle.await;
    }

    Ok(())
}

// ---- Helpers ----

fn load_identity(keyfile: &str, no_passphrase: bool) -> Result<Identity> {
    nie_core::keyfile::load_identity(keyfile, no_passphrase)
}

/// Encrypt the 64-byte keyfile payload (Ed25519_seed || X25519_seed) with a
/// passphrase using the age format.
fn encrypt_keyfile(seed: &[u8; 64], passphrase: &str) -> Result<Vec<u8>> {
    nie_core::keyfile::encrypt_keyfile(seed, passphrase)
}

/// Decrypt an age-encrypted keyfile and return the 64-byte payload
/// (Ed25519_seed || X25519_seed).
fn decrypt_keyfile(ciphertext: &[u8], passphrase: &str) -> Result<[u8; 64]> {
    nie_core::keyfile::decrypt_keyfile(ciphertext, passphrase)
}

/// Broadcast own profile to the room.  Returns `false` if the send channel
/// is closed (caller should break the event loop).
/// Skips silently if `profile` is empty — no point broadcasting nothing.
async fn send_profile_broadcast(
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    profile: &std::collections::HashMap<String, String>,
    mls_active: bool,
    mls: &mut nie_core::mls::MlsClient,
) -> bool {
    if profile.is_empty() {
        return true;
    }
    // serde_json::to_vec on derived Serialize cannot fail
    let bytes = serde_json::to_vec(&ClearMessage::Profile {
        fields: profile.clone(),
    })
    .unwrap();
    let payload = if mls_active {
        match mls.encrypt(&bytes) {
            Ok(ct) => match nie_core::messages::pad(&ct) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("pad profile: {e}");
                    return true; // channel still alive, skip this message
                }
            },
            Err(e) => {
                tracing::warn!("MLS encrypt profile: {e}");
                bytes
            }
        }
    } else {
        bytes
    };
    // JsonRpcRequest::new on derived Serialize params cannot fail
    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload },
    )
    .unwrap();
    tx.send(req).await.is_ok()
}

/// Re-send the last outgoing PaymentAction for every in-flight session whose peer
/// is currently online.  Called once per MLS activation (nie-0aj).
///
/// "In-flight" means Payer+Requested or Payee+AddressProvided — states where the
/// peer is waiting for a message that may have been lost if we restarted.
///
/// Returns `false` if the send channel is closed (caller should break the event loop).
/// Re-broadcast in-flight payment sessions to peers that just came online.
///
/// **Precondition: MLS must be active.**  Both call sites are guarded by
/// `if mls_active { }`.  This function always passes `mls_active = true`
/// to `send_payment_message` — do not call it from a non-MLS code path.
async fn resync_sessions(
    sessions: &HashMap<Uuid, PaymentSession>,
    online: &[String],
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    mls: &mut nie_core::mls::MlsClient,
) -> bool {
    let mut n = 0u32;
    for (&sid, s) in sessions {
        if !online.contains(&s.peer_pub_id) {
            continue;
        }
        let action = match (&s.role, &s.state) {
            (PaymentRole::Payer, PaymentState::Requested) => PaymentAction::Request {
                chain: s.chain,
                amount_zatoshi: s.amount_zatoshi,
            },
            (PaymentRole::Payee, PaymentState::AddressProvided) => {
                // address is guaranteed Some for AddressProvided payee sessions.
                let Some(addr) = s.address.clone() else {
                    continue;
                };
                PaymentAction::Address {
                    chain: s.chain,
                    address: addr,
                }
            }
            (PaymentRole::Payer, PaymentState::Sent) => {
                // tx_hash is guaranteed Some once state reaches Sent.
                let Some(tx_hash) = s.tx_hash.clone() else {
                    tracing::warn!("Payer/Sent session {sid} has no tx_hash — cannot resync");
                    continue;
                };
                PaymentAction::Sent {
                    chain: s.chain,
                    tx_hash,
                    amount_zatoshi: s.amount_zatoshi,
                }
            }
            (PaymentRole::Payee, PaymentState::Sent) => {
                // tx_hash is stored at transition time (dispatch_payment line 1667)
                // before the Sent upsert, so it is guaranteed Some here.  If somehow
                // missing (corrupt DB row), skip and warn rather than panic.
                let Some(tx_hash) = s.tx_hash.clone() else {
                    tracing::warn!("Payee/Sent session {sid} has no tx_hash — cannot resync");
                    continue;
                };
                PaymentAction::Confirmed { tx_hash }
            }
            _ => continue,
        };
        // true: both call sites are inside `if mls_active { }` blocks.
        if !send_payment_message(sid, action, tx, true, mls).await {
            return false;
        }
        n += 1;
    }
    if n > 0 {
        println!("[pay] Resumed {n} active payment session(s).");
    }
    // Payer/AddressProvided sessions have the address stored locally — no peer
    // message is needed — but the payer needs a reminder to act.  Auto-payment
    // already fired when the address was first received; on reconnect it does
    // not re-fire because send_fn is not accessible here.  Print a visible
    // prompt so the user knows the session needs attention.
    for (&sid, s) in sessions {
        if s.role == PaymentRole::Payer && s.state == PaymentState::AddressProvided {
            let short = &sid.to_string()[..8];
            println!(
                "[pay] Pending payment to {} is awaiting your action. \
                 Run /confirm {short} to send, or /cancel {short} to abort.",
                &s.peer_pub_id[..s.peer_pub_id.len().min(8)]
            );
        }
    }
    true
}

/// Encrypt and broadcast a `ClearMessage::Payment` to the room.
///
/// Payment messages go via Broadcast (MLS-encrypted when active) rather than
/// Whisper so the relay stays blind to payment negotiation — it cannot
/// distinguish a payment message from a chat message.  Recipients filter by
/// `session_id`; the MLS layer ensures confidentiality.
///
/// Returns `false` if the send channel is closed (caller should break the loop).
async fn send_payment_message(
    session_id: Uuid,
    action: PaymentAction,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    mls_active: bool,
    mls: &mut nie_core::mls::MlsClient,
) -> bool {
    let msg = ClearMessage::Payment { session_id, action };
    // serde_json::to_vec on derived Serialize cannot fail
    let bytes = serde_json::to_vec(&msg).unwrap();
    let payload = if mls_active {
        match mls.encrypt(&bytes) {
            Ok(ct) => match nie_core::messages::pad(&ct) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("\r[payment] payload padding failed ({e}); cannot send.");
                    return true; // channel still alive
                }
            },
            Err(e) => {
                // Encryption failed — do not send plaintext payment data.
                eprintln!("\r[payment] MLS encryption failed ({e}); cannot send.");
                return true; // channel still alive
            }
        }
    } else {
        bytes
    };
    // JsonRpcRequest::new on derived Serialize params cannot fail
    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::BROADCAST,
        BroadcastParams { payload },
    )
    .unwrap();
    tx.send(req).await.is_ok()
}

/// Generate a fresh diversified Unified Address for the payment account.
///
/// Returns `Ok(ua_string)` on success, or `Err(PaymentAction::Unknown)` with a
/// reason string the caller can forward to the payer.  All DB and derivation
/// errors are logged internally; the returned `PaymentAction::Unknown` is safe
/// to send on the wire.
async fn generate_fresh_address(
    fvks: &WalletFvks,
    wallet_store: &WalletStore,
) -> Result<String, PaymentAction> {
    let start = wallet_store
        .next_diversifier(PAYMENT_ACCOUNT)
        .await
        .map_err(|e| {
            warn!("next_diversifier failed: {e}");
            PaymentAction::Unknown {
                reason: "wallet error".to_string(),
            }
        })?;

    let (found_di, addr) = diversified_address(&fvks.sapling, &fvks.orchard, start, fvks.network)
        .map_err(|e| {
        warn!("diversified_address failed: {e}");
        PaymentAction::Unknown {
            reason: "address generation failed".to_string(),
        }
    })?;

    info!("issued fresh subaddress at diversifier index {}", found_di);

    // When Sapling skipped invalid diversifiers (found_di > start), advance the
    // DB past found_di before returning.  If this write fails, the next request
    // would map to the same found_di and reuse the same UA — breaking unlinkability.
    if found_di > start {
        wallet_store
            .advance_diversifier_to(PAYMENT_ACCOUNT, found_di + 1)
            .await
            .map_err(|e| {
                warn!("advance_diversifier_to failed after Sapling skip: {e}");
                PaymentAction::Unknown {
                    reason: "wallet error; try again".to_string(),
                }
            })?;
    }

    Ok(addr)
}

/// ZIP-32 account index used for all payment address derivation.
/// nie uses a single-account wallet; all payment operations share account 0.
const PAYMENT_ACCOUNT: u32 = 0;

/// Route an incoming `ClearMessage::Payment` to the correct session handler.
///
/// Dispatches on (role, state, action) to advance the payment state machine.
/// New session + Request → payee path.  Known session → payer or payee transition
/// based on current state.  Messages from non-party peers are silently dropped.
///
/// Returns `false` if the send channel is closed (caller should break the loop).
#[allow(clippy::too_many_arguments)]
async fn dispatch_payment(
    session_id: Uuid,
    action: PaymentAction,
    from: &str,
    sessions: &mut HashMap<Uuid, PaymentSession>,
    wallet_store: &WalletStore,
    wallet_fvks: Option<&WalletFvks>,
    nicknames: &HashMap<String, String>,
    local_names: &HashMap<String, String>,
    tx: &tokio::sync::mpsc::Sender<JsonRpcRequest>,
    mls_active: bool,
    mls: &mut nie_core::mls::MlsClient,
    send_fn: Option<&SendFn>,
    watch_registry: Option<&AddressWatchRegistry>,
) -> bool {
    match sessions.entry(session_id) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            // Guard: ignore messages from peers not party to this session.  In rooms
            // with N>2 users, non-involved peers receive every payment broadcast and
            // reply Unknown.  Without this check those replies could reach an Occupied
            // handler and drive an unintended state transition.  (nie-2f8)
            if from != entry.get().peer_pub_id {
                return true;
            }
            let role = entry.get().role.clone();
            let state = entry.get().state.clone();
            let short_id = session_id.to_string();
            let short_id = &short_id[..8];
            match (role, state, action) {
                // nie-c20: Payer receives Address → auto-send via send_fn, or prompt /confirm
                (
                    PaymentRole::Payer,
                    PaymentState::Requested,
                    PaymentAction::Address { address, .. },
                ) => {
                    // Extract metadata before mutably borrowing the entry.
                    let (amount_zatoshi, chain_clone) = {
                        let s = entry.get();
                        (s.amount_zatoshi, s.chain)
                    };
                    // Persist AddressProvided state.
                    {
                        let session = entry.get_mut();
                        session.state = PaymentState::AddressProvided;
                        session.address = Some(address.clone());
                        session.updated_at = chrono::Utc::now().timestamp();
                        if let Err(e) = wallet_store.upsert_session(session).await {
                            warn!("failed to persist payer AddressProvided for {session_id}: {e}");
                        }
                    }
                    if let Some(sf) = send_fn {
                        println!(
                            "[pay] Received address from {}. Broadcasting {} zatoshi...",
                            display_name(from, nicknames, local_names),
                            amount_zatoshi
                        );
                        match sf(address.clone(), amount_zatoshi, session_id).await {
                            Ok(txid) => {
                                println!("[pay] Payment sent. Txid: {txid}");
                                {
                                    let session = entry.get_mut();
                                    session.state = PaymentState::Sent;
                                    session.tx_hash = Some(txid.clone());
                                    session.updated_at = chrono::Utc::now().timestamp();
                                    if let Err(e) = wallet_store.upsert_session(session).await {
                                        warn!("failed to persist payer Sent for {session_id}: {e}");
                                    }
                                }
                                if !send_payment_message(
                                    session_id,
                                    PaymentAction::Sent {
                                        chain: chain_clone,
                                        tx_hash: txid,
                                        amount_zatoshi,
                                    },
                                    tx,
                                    mls_active,
                                    mls,
                                )
                                .await
                                {
                                    return false;
                                }
                            }
                            Err(SendPaymentError::SyncLag(e)) => {
                                println!("[pay] Payment blocked: {e}");
                                println!(
                                    "[pay] Run 'nie wallet sync', then type /confirm \
                                     {short_id} to retry."
                                );
                            }
                            Err(SendPaymentError::Build(
                                nie_wallet::tx_error::TxBuildError::InsufficientFunds { .. },
                            )) => {
                                println!("[pay] Insufficient ZEC to complete payment.");
                                println!(
                                    "[pay] Deposit ZEC, then type /confirm {short_id} to retry."
                                );
                            }
                            Err(e) => {
                                println!("[pay] Payment error: {e}");
                                if !send_payment_message(
                                    session_id,
                                    PaymentAction::Unknown {
                                        reason: format!("payment error: {e}"),
                                    },
                                    tx,
                                    mls_active,
                                    mls,
                                )
                                .await
                                {
                                    return false;
                                }
                            }
                        }
                    } else {
                        println!(
                            "[pay] Address received from {}: {address}.",
                            display_name(from, nicknames, local_names)
                        );
                        println!("[pay] Send payment then type /confirm {short_id} to confirm.");
                    }
                    true
                }
                // nie-6sp: Payee receives Sent → record tx_hash, wait for on-chain confirmation
                (
                    PaymentRole::Payee,
                    PaymentState::AddressProvided,
                    PaymentAction::Sent {
                        tx_hash, chain: _, ..
                    },
                ) => {
                    println!(
                        "[pay] Payer broadcast tx {}. Watching for confirmation...",
                        &tx_hash[..tx_hash.len().min(16)]
                    );
                    let session = entry.get_mut();
                    session.state = PaymentState::Sent;
                    session.tx_hash = Some(tx_hash.clone());
                    session.updated_at = chrono::Utc::now().timestamp();
                    if let Err(e) = wallet_store.upsert_session(session).await {
                        warn!("failed to persist payee Sent for {session_id}: {e}");
                    }
                    true
                }
                // nie-6sp: Payee receives Unknown → session failed
                (
                    PaymentRole::Payee,
                    PaymentState::AddressProvided,
                    PaymentAction::Unknown { reason },
                ) => {
                    println!("[pay] Payment failed: {reason}");
                    let session = entry.get_mut();
                    session.state = PaymentState::Failed;
                    session.updated_at = chrono::Utc::now().timestamp();
                    if let Err(e) = wallet_store.upsert_session(session).await {
                        warn!("failed to persist payee Failed for {session_id}: {e}");
                    }
                    true
                }
                // nie-c1v: Payer receives Confirmed → session complete
                (PaymentRole::Payer, PaymentState::Sent, PaymentAction::Confirmed { tx_hash }) => {
                    // Validate: must be exactly 64 lowercase hex chars (canonical Zcash txid).
                    if tx_hash.len() != 64
                        || !tx_hash
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
                    {
                        warn!(
                            "received Confirmed with malformed tx_hash '{}'; rejecting",
                            tx_hash
                        );
                        return false;
                    }
                    let amount_zatoshi = entry.get().amount_zatoshi;
                    println!(
                        "[pay] {} ZEC confirmed (tx {}). Session complete.",
                        zatoshi_to_zec_string(amount_zatoshi),
                        &tx_hash[..16]
                    );
                    info!("Payment confirmed: session={session_id} txid={tx_hash}");
                    let session = entry.get_mut();
                    session.state = PaymentState::Confirmed;
                    session.tx_hash = Some(tx_hash);
                    session.updated_at = chrono::Utc::now().timestamp();
                    if let Err(e) = wallet_store.upsert_session(session).await {
                        warn!("failed to persist payer Confirmed for {session_id}: {e}");
                    }
                    true
                }
                // nie-c1v: Payer receives Unknown in any state → session failed
                (PaymentRole::Payer, _, PaymentAction::Unknown { reason }) => {
                    println!("[pay] Session {short_id} failed: {reason}");
                    let session = entry.get_mut();
                    session.state = PaymentState::Failed;
                    session.updated_at = chrono::Utc::now().timestamp();
                    if let Err(e) = wallet_store.upsert_session(session).await {
                        warn!("failed to persist payer Failed for {session_id}: {e}");
                    }
                    true
                }
                // nie-0bj: peer cancels the session → transition to Expired
                (_, _, PaymentAction::Cancelled { reason }) => {
                    println!("[pay] Session {short_id} cancelled by peer: {reason}");
                    let session = entry.get_mut();
                    session.state = PaymentState::Expired;
                    session.updated_at = chrono::Utc::now().timestamp();
                    if let Err(e) = wallet_store.upsert_session(session).await {
                        warn!("failed to persist cancelled session {session_id}: {e}");
                    }
                    true
                }
                // Unhandled combination — log for debugging.
                (_, _, action) => {
                    warn!(
                        "payment action {:?} unhandled for session {session_id} \
                         (role={:?}, state={:?})",
                        action,
                        entry.get().role,
                        entry.get().state
                    );
                    true
                }
            }
        }
        std::collections::hash_map::Entry::Vacant(slot) => {
            if let PaymentAction::Request { chain, amount_zatoshi } = action {
                // Payee receives a new payment request.  Create a payee session and
                // immediately respond with a fresh Sapling+Orchard subaddress.
                // Payee dust guard: mirror the payer-side check.  A peer running an
                // older or non-conformant client can send a Request with amount below
                // DUST_THRESHOLD (where the fee would equal or exceed the transfer).
                // Accepting it wastes a diversifier index and enters a payment session
                // that can never complete economically.
                if amount_zatoshi < DUST_THRESHOLD {
                    warn!(
                        "payee: rejecting dust request ({amount_zatoshi} zatoshi < {DUST_THRESHOLD}) from {}",
                        &from[..from.len().min(8)]
                    );
                    println!(
                        "[pay] Cannot fulfill payment request from {}: amount {} ZEC is below dust threshold.",
                        display_name(from, nicknames, local_names),
                        zatoshi_to_zec_string(amount_zatoshi)
                    );
                    return send_payment_message(
                        session_id,
                        PaymentAction::Unknown {
                            reason: format!(
                                "amount {amount_zatoshi} zatoshi is below dust threshold {DUST_THRESHOLD}"
                            ),
                        },
                        tx,
                        mls_active,
                        mls,
                    )
                    .await;
                }
                // Generate a fresh Sapling+Orchard subaddress via the wallet FVKs.
                // Returns Unknown to the payer if the wallet is not available.
                let address = match wallet_fvks {
                    None => {
                        println!(
                            "[pay] Wallet not initialized — cannot generate a receive address."
                        );
                        println!("[pay] Run `nie wallet init` to set up a Zcash wallet.");
                        return send_payment_message(
                            session_id,
                            PaymentAction::Unknown {
                                reason: "wallet not initialized".to_string(),
                            },
                            tx,
                            mls_active,
                            mls,
                        )
                        .await;
                    }
                    Some(fvks) => match generate_fresh_address(fvks, wallet_store).await {
                        Ok(addr) => addr,
                        Err(unknown) => {
                            return send_payment_message(session_id, unknown, tx, mls_active, mls)
                                .await;
                        }
                    },
                };
                let now = chrono::Utc::now().timestamp();
                let payee_session = PaymentSession {
                    id: session_id,
                    chain,
                    amount_zatoshi,
                    peer_pub_id: from.to_string(),
                    role: PaymentRole::Payee,
                    state: PaymentState::AddressProvided,
                    created_at: now,
                    updated_at: now,
                    tx_hash: None,
                    address: Some(address.clone()),
                };
                if let Err(e) = wallet_store.upsert_session(&payee_session).await {
                    warn!("failed to persist payee session {session_id}: {e}");
                }
                slot.insert(payee_session);

                // Register the Sapling bytes of this address in the watch registry so the
                // block watcher can match decrypted notes to this session.
                // The registry key is hex(Sapling address bytes[43]) extracted from the UA.
                if let Some(reg) = watch_registry {
                    if let Ok((_net, ua)) = decode_unified_address(&address) {
                        if let Some(sapling_bytes) = sapling_receiver(&ua) {
                            let key: String =
                                sapling_bytes.iter().map(|b| format!("{b:02x}")).collect();
                            reg.register(key, session_id);
                        }
                    }
                }

                println!(
                    "[pay] payment request from {}. Responding with address {address}.",
                    display_name(from, nicknames, local_names)
                );
                send_payment_message(
                    session_id,
                    PaymentAction::Address { chain, address },
                    tx,
                    mls_active,
                    mls,
                )
                .await
            } else {
                // Non-Request for a session we don't recognise.  Tell the sender we
                // lost the session (e.g. app restart) so they can handle it gracefully.
                send_payment_message(
                    session_id,
                    PaymentAction::Unknown {
                        reason: "session not found".to_string(),
                    },
                    tx,
                    mls_active,
                    mls,
                )
                .await
            }
        }
    }
}

/// True if this client is currently the MLS group admin.
///
/// Admin = the peer with the lowest connection sequence in `online`, which is
/// always `online[0]` because `online` is kept sorted ascending by sequence.
fn is_admin(online: &[String], my_pub_id: &str) -> bool {
    online.first().map(|s| s.as_str()) == Some(my_pub_id)
}

/// Display name: server nickname > local alias > shortid.
/// `nicknames` contains names set via /iam (server-side, authoritative).
/// `local_names` contains names set via /alias (client-side, persistent).
fn display_name(
    pub_id: &str,
    nicknames: &HashMap<String, String>,
    local_names: &HashMap<String, String>,
) -> String {
    let short = PubId(pub_id.to_string()).short();
    let name = nicknames.get(pub_id).or_else(|| local_names.get(pub_id));
    if let Some(n) = name {
        format!("{n} ({short})")
    } else {
        short
    }
}

/// Stable ANSI color for a pub_id, derived from its first byte.
/// Uses bright variants (91-96) for visibility on both dark and light terminals.
fn color_for(pub_id: &str) -> u8 {
    const COLORS: &[u8] = &[91, 92, 93, 94, 95, 96];
    // Use get(..2) instead of indexing so a short or empty pub_id (e.g. from a
    // buggy/hostile relay) returns a default color rather than panicking.
    let byte = pub_id
        .get(..2)
        .and_then(|s| u8::from_str_radix(s, 16).ok())
        .unwrap_or(0) as usize;
    COLORS[byte % COLORS.len()]
}

fn colored_name(
    pub_id: &str,
    nicknames: &HashMap<String, String>,
    local_names: &HashMap<String, String>,
) -> String {
    format!(
        "\x1b[{}m{}\x1b[0m",
        color_for(pub_id),
        display_name(pub_id, nicknames, local_names)
    )
}

/// Format a Unix-seconds timestamp as HH:MM in local time.
fn format_ts(unix_secs: i64) -> String {
    use chrono::TimeZone;
    Local
        .timestamp_opt(unix_secs, 0)
        .single()
        .map(|dt| dt.format("%H:%M").to_string())
        .unwrap_or_else(|| "??:??".to_string())
}

/// Build the ordered list of lightwalletd endpoints to try.
///
/// Priority: user-supplied URL (from `--lightwalletd` or config.toml) >
/// network-default constants.
fn resolve_lwd_endpoints(lightwalletd: Option<&str>, network: ZcashNetwork) -> Vec<String> {
    if let Some(url) = lightwalletd {
        vec![url.to_owned()]
    } else {
        match network {
            ZcashNetwork::Mainnet => DEFAULT_MAINNET_ENDPOINTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ZcashNetwork::Testnet => vec![DEFAULT_TESTNET_ENDPOINT.to_string()],
        }
    }
}

/// Resolve a display name or pub_id to a pub_id string.
///
/// Resolution order: exact pub_id (must be in `online`) → server nickname
/// (case-insensitive) → local alias (case-insensitive).  Returns `Err` if
/// nothing matches.
fn resolve_handle(
    handle: &str,
    online: &[String],
    nicknames: &HashMap<String, String>,
    local_names: &HashMap<String, String>,
) -> Result<String, String> {
    // Direct pub_id match.
    if online.iter().any(|id| id == handle) {
        return Ok(handle.to_string());
    }
    // Server nickname (/iam).
    for (pub_id, nick) in nicknames {
        if nick.eq_ignore_ascii_case(handle) && online.contains(pub_id) {
            return Ok(pub_id.clone());
        }
    }
    // Local alias (/alias).
    for (pub_id, alias) in local_names {
        if alias.eq_ignore_ascii_case(handle) && online.contains(pub_id) {
            return Ok(pub_id.clone());
        }
    }
    Err(format!("'{handle}' is not online or not recognized"))
}


/// Returns a help string for slash commands, or None if it's not a slash command.
fn handle_slash(line: &str) -> Option<String> {
    match line {
        "/quit" | "/q" => Some("bye.".to_string()),
        "/help" | "/h" => Some(
            "/quit              — exit chat\n\
             /help              — this message\n\
             /iam <name>        — set server-visible nickname\n\
             /alias <name> <id> — save local alias for a pub_id\n\
             /who               — list users currently online\n\
             /me <action>       — send an action message (* you wave)\n\
             /cat <path>        — send contents of a text file (max 4KB)\n\
             /! <cmd> [args]    — run command and send stdout (no shell; max 4KB)\n\
             /clear             — clear terminal\n\
             /pay <h> <amt> [chain] — initiate a payment (zcash/monero/mobilecoin)\n\
             /confirm <short_id>    — confirm payment sent after receiving an address\n\
             /balance               — show shielded ZEC balance\n\
             /receive               — show your Unified Address\n\
             /payments              — list payment session history\n\
             /subscribe <days>      — request a subscription invoice\n\
             /group create <name>   — create a named group channel\n\
             /group list            — list your groups\n\
             /group leave <name>    — leave a group\n\
             /group send <name> <text> — send message to a group"
                .to_string(),
        ),
        "/pay" => Some("usage: /pay <handle> <amount> [zcash|monero|mobilecoin]".to_string()),
        "/confirm" => Some("usage: /confirm <short_session_id>".to_string()),
        "/balance" => Some("usage: /balance".to_string()),
        "/receive" => Some("usage: /receive".to_string()),
        "/payments" => Some("usage: /payments".to_string()),
        s if s.starts_with('/') => Some(format!("unknown command: {s}")),
        _ => None,
    }
}

// ---- Wallet FVK loading (for payment address generation) ----

/// Cached full viewing keys derived from the wallet master key.
///
/// Loaded once at chat startup; held for the lifetime of the session so
/// address generation and payment sending in `dispatch_payment` require no
/// additional I/O at request time.
struct WalletFvks {
    network: ZcashNetwork,
    sapling: SaplingDiversifiableFvk,
    orchard: OrchardFullViewingKey,
    /// Spending key — needed to authorise payment proofs.  Wrapped in Arc so
    /// the production `send_fn` closure can clone a cheap handle without
    /// duplicating the key bytes on every payment.
    sapling_sk: Arc<SaplingExtendedSpendingKey>,
}

/// Async closure type for sending a Zcash payment.
///
/// Parameters: `(to_address, amount_zatoshi, session_id)`.
/// Returns the txid on success.
type SendFn = dyn Fn(
        String,
        u64,
        Uuid,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, SendPaymentError>> + Send>>
    + Send
    + Sync;

/// Attempt to load and decrypt wallet.key, derive Sapling DFVK and Orchard FVK.
///
/// Returns `None` if:
/// - `wallet.key` does not exist (wallet not initialized)
/// - Decryption fails (wrong passphrase)
/// - Key derivation fails (corrupt key material)
///
/// Failures are logged at `warn!` level so the caller can continue without
/// wallet capability; a user-visible error is printed when decryption fails.
fn try_load_wallet_fvks(
    data_dir: &Path,
    no_passphrase: bool,
    expected_network: &str,
) -> Option<WalletFvks> {
    let wallet_key_path = data_dir.join("wallet.key");
    if !wallet_key_path.exists() {
        return None;
    }

    let ciphertext = match std::fs::read(&wallet_key_path) {
        Ok(b) => b,
        Err(e) => {
            warn!("failed to read wallet.key: {e}");
            return None;
        }
    };

    let passphrase = if no_passphrase {
        String::new()
    } else {
        match rpassword::prompt_password("Wallet passphrase (press Enter to skip): ") {
            Ok(p) => p,
            Err(e) => {
                warn!("failed to read wallet passphrase: {e}");
                return None;
            }
        }
    };

    // Empty passphrase means the user left the field blank — wallet will be
    // unavailable for this session.
    let key_bytes = match decrypt_wallet_key(&ciphertext, &passphrase) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[wallet] failed to decrypt wallet.key: {e}");
            eprintln!(
                "[wallet] Payment address generation disabled. Restart nie chat to try again."
            );
            return None;
        }
    };

    let meta = match WalletMeta::load(data_dir) {
        Ok(Some(m)) => m,
        Ok(None) => {
            warn!("wallet.key exists but wallet.json missing — network unknown");
            return None;
        }
        Err(e) => {
            warn!("failed to read wallet.json: {e}");
            return None;
        }
    };

    // Network mismatch: disable wallet for this session rather than aborting chat.
    // Chat works without a wallet; deriving FVKs on the wrong network would produce
    // addresses for the wrong chain, which is the actual danger to guard against.
    if meta.network != expected_network {
        println!(
            "[wallet] Wallet was created for {}; payment features disabled for this {} session.",
            meta.network, expected_network
        );
        println!(
            "[wallet] Use --network {} to enable payments, or run `nie wallet init` for {}.",
            meta.network, expected_network
        );
        return None;
    }

    let network = match meta.network.as_str() {
        "mainnet" => ZcashNetwork::Mainnet,
        "testnet" => ZcashNetwork::Testnet,
        other => {
            warn!("unknown network '{}' in wallet.json", other);
            return None;
        }
    };

    let sapling_sk = SaplingExtendedSpendingKey::from_seed(&key_bytes, network, 0);
    let orchard_sk = match OrchardSpendingKey::from_seed(&key_bytes, network, 0) {
        Ok(sk) => sk,
        Err(e) => {
            warn!("Orchard key derivation failed: {e}");
            return None;
        }
    };

    let dfvk = sapling_sk.to_dfvk();
    Some(WalletFvks {
        network,
        sapling: dfvk,
        orchard: orchard_sk.to_fvk(),
        sapling_sk: Arc::new(sapling_sk),
    })
}

// ---- Wallet metadata (network tag) ----

/// Plaintext metadata stored alongside wallet.key.
/// Not a secret — network type is not key material.
#[derive(Debug, Serialize, Deserialize)]
struct WalletMeta {
    network: String,
}

impl WalletMeta {
    fn load(data_dir: &Path) -> Result<Option<Self>> {
        let path = data_dir.join("wallet.json");
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)?;
        let meta: Self =
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("wallet.json corrupt: {e}"))?;
        Ok(Some(meta))
    }

    fn save(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join("wallet.json");
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// Validate that --network matches the wallet's stored network.
///
/// Called before any command that would use the wallet.  If wallet.json does not
/// yet exist the check is skipped (wallet has not been initialized).
pub fn check_network_guard(data_dir: &Path, network: &str) -> Result<()> {
    let Some(meta) = WalletMeta::load(data_dir)? else {
        return Ok(());
    };
    if meta.network != network {
        bail!(
            "This wallet was created for {}.  \
             Use --network {} or create a new {} wallet.",
            meta.network,
            meta.network,
            network
        );
    }
    Ok(())
}

// ---- Wallet key encryption / decryption ----

/// Encrypt a 64-byte ZIP-32 master key with a passphrase using the age format.
fn encrypt_wallet_key(key_bytes: &[u8; 64], passphrase: &str) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
    let mut output = vec![];
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| anyhow::anyhow!("age encrypt error: {e}"))?;
    writer.write_all(key_bytes)?;
    writer
        .finish()
        .map_err(|e| anyhow::anyhow!("age finish error: {e}"))?;
    Ok(output)
}

/// Decrypt an age-encrypted wallet.key and return the 64-byte ZIP-32 master key.
fn decrypt_wallet_key(ciphertext: &[u8], passphrase: &str) -> Result<[u8; 64]> {
    let decryptor = Decryptor::new(ciphertext)
        .map_err(|e| anyhow::anyhow!("wallet.key corrupt or unrecognized format: {e}"))?;
    let pass_decryptor = match decryptor {
        Decryptor::Passphrase(d) => d,
        _ => bail!("wallet.key was not encrypted with a passphrase"),
    };
    let mut reader = pass_decryptor
        .decrypt(&Secret::new(passphrase.to_owned()), None)
        .map_err(|_| anyhow::anyhow!("wrong passphrase or corrupt wallet.key"))?;
    let mut plaintext = vec![];
    reader.read_to_end(&mut plaintext)?;
    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("wallet.key corrupt: unexpected length after decryption"))
}

// ---- Wallet commands ----

/// `nie wallet init` — generate a new Zcash wallet from OS entropy.
///
/// Displays the 24-word BIP-39 mnemonic once and saves the encrypted ZIP-32
/// master key to wallet.key.  Refuses to overwrite an existing wallet.key
/// unless `force` is true.
pub async fn wallet_init(
    data_dir: &Path,
    network: &str,
    no_passphrase: bool,
    force: bool,
) -> Result<()> {
    let wallet_key_path = data_dir.join("wallet.key");

    if wallet_key_path.exists() && !force {
        bail!(
            "wallet.key already exists at {}.  \
             Use --force to overwrite (THIS WILL DESTROY YOUR EXISTING WALLET).",
            wallet_key_path.display()
        );
    }

    // nie-vz1: network guard — refuse to overwrite a wallet created for a different network.
    if wallet_key_path.exists() && force {
        check_network_guard(data_dir, network)?;
    }

    // Generate BIP-39 mnemonic, ZIP-32 master key, and BIP-39 seed.
    // seed is what gets stored in wallet.key — it is the input both
    // SaplingExtendedSpendingKey::from_seed and OrchardSpendingKey::from_seed expect.
    // master is only used for the key-separation check below; it is not stored.
    let (words, master, seed) = nie_core::wallet::generate_wallet()?;

    // nie-dfu: key separation invariant.  The wallet spending key and the Ed25519 identity
    // seed are generated from independent entropy.  The probability of collision is
    // astronomically small, but assert anyway — a match indicates an RNG catastrophe.
    //
    // Key separation check only in --no-passphrase mode (CI/testing).
    // In normal (passphrase) mode this check is skipped — key separation is
    // enforced by independent OsRng calls, not a runtime assertion.  Adding a
    // second passphrase prompt here would degrade UX for a defense-in-depth check.
    let identity_key_path = data_dir.join("identity.key");
    if identity_key_path.exists() && no_passphrase {
        let id_ciphertext = std::fs::read(&identity_key_path)?;
        if let Ok(id_seed) = decrypt_keyfile(&id_ciphertext, "") {
            // Compare only the Ed25519 portion (first 32 bytes of the 64-byte keyfile).
            anyhow::ensure!(
                id_seed[0..32] != *master.spending_key_bytes(),
                "key separation violation: wallet spending key matches identity key \
                 (catastrophic RNG failure — do not use this wallet)"
            );
        }
    }

    let passphrase = if no_passphrase {
        eprintln!("WARNING: --no-passphrase set. Wallet key will NOT be encrypted.");
        String::new()
    } else {
        let p = rpassword::prompt_password("Wallet passphrase: ")?;
        let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
        anyhow::ensure!(p == p2, "passphrases do not match");
        p
    };

    let encrypted = encrypt_wallet_key(&seed, &passphrase)?;
    std::fs::write(&wallet_key_path, &encrypted)?;

    // Paranoid write-verify: immediately decrypt and compare.
    // Detects file-system corruption or age bugs before the mnemonic display is dismissed.
    let recovered = decrypt_wallet_key(&encrypted, &passphrase)?;
    anyhow::ensure!(
        recovered == seed,
        "wallet.key write verification failed — file may be corrupt, do not dismiss the mnemonic"
    );

    // Write network metadata.
    WalletMeta {
        network: network.to_owned(),
    }
    .save(data_dir)?;

    // Display mnemonic — shown exactly once, never stored.
    println!("Zcash wallet created ({network})");
    println!();
    println!("WRITE DOWN your 24-word recovery phrase.  It will not be shown again.");
    println!("Anyone with these words can access your funds.");
    println!();
    for (chunk_idx, row) in words.chunks(4).enumerate() {
        let start = chunk_idx * 4 + 1;
        for (j, word) in row.iter().enumerate() {
            print!("{:2}. {:<12}", start + j, word);
        }
        println!();
    }
    println!();
    println!("wallet.key : {}", wallet_key_path.display());

    Ok(())
}

/// `nie wallet restore` — restore a Zcash wallet from a BIP-39 mnemonic.
///
/// Prompts for the 24-word phrase interactively.  Refuses to overwrite an
/// existing wallet.key unless `force` is true.
pub async fn wallet_restore(
    data_dir: &Path,
    network: &str,
    no_passphrase: bool,
    force: bool,
) -> Result<()> {
    let wallet_key_path = data_dir.join("wallet.key");

    if wallet_key_path.exists() && !force {
        bail!(
            "wallet.key already exists at {}.  \
             Use --force to overwrite.",
            wallet_key_path.display()
        );
    }

    // nie-vz1: network guard — refuse to restore over a different-network wallet.
    if wallet_key_path.exists() && force {
        check_network_guard(data_dir, network)?;
    }

    // Prompt for mnemonic with visible input (rustyline).
    // The mnemonic is on paper; shoulder-surfing is not the threat model.
    // Hidden input for 24 words is practically unusable — no way to spot typos.
    println!("Enter your 24-word recovery phrase (words separated by spaces):");
    let mut rl = rustyline::DefaultEditor::new()
        .map_err(|e| anyhow::anyhow!("readline init failed: {e}"))?;
    let phrase = rl
        .readline("> ")
        .map_err(|e| anyhow::anyhow!("mnemonic input failed: {e}"))?;
    let phrase = phrase.trim().to_string();
    if phrase.split_whitespace().count() < 12 {
        bail!("too few words — expected a 24-word BIP-39 mnemonic");
    }

    // restore_wallet returns (master, seed); seed is stored in wallet.key.
    // master is not stored — it is only available here for a potential key-separation
    // check if one is added in future.
    let (_master, seed) = nie_core::wallet::restore_wallet(&phrase)?;

    let passphrase = if no_passphrase {
        eprintln!("WARNING: --no-passphrase set. Wallet key will NOT be encrypted.");
        String::new()
    } else {
        let p = rpassword::prompt_password("Wallet passphrase: ")?;
        let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
        anyhow::ensure!(p == p2, "passphrases do not match");
        p
    };

    let encrypted = encrypt_wallet_key(&seed, &passphrase)?;
    std::fs::write(&wallet_key_path, &encrypted)?;

    // Paranoid write-verify.
    let recovered = decrypt_wallet_key(&encrypted, &passphrase)?;
    anyhow::ensure!(
        recovered == seed,
        "wallet.key write verification failed — file may be corrupt"
    );

    WalletMeta {
        network: network.to_owned(),
    }
    .save(data_dir)?;

    println!("wallet restored ({network})");
    println!("wallet.key : {}", wallet_key_path.display());

    Ok(())
}

// ---- Background block watcher (nie-ghf + nie-hll) ----

/// Minimum confirmation depth before a payment is considered confirmed.
///
/// 10 confirmations is the Zcash spec value for shielded finality.
const MIN_CONFIRMATIONS: u64 = 10;

/// Spawn the background Sapling block watcher task.
///
/// Polls lightwalletd every ~75 seconds (one Zcash block interval), trial-decrypts
/// Sapling outputs using the provided IVK bytes, and fires [`ConfirmationEvent`]s
/// when a watched address reaches [`MIN_CONFIRMATIONS`] depth.
///
/// Confirmation depth state (nie-hll) is maintained inside this task as a local
/// `pending` map: `txid → (session_id, found_at_height)`.  Entries are removed and
/// a [`ConfirmationEvent`] is sent once `current_height - found_at_height >= MIN_CONFIRMATIONS`.
///
/// # Parameters
/// - `ivk_bytes`: 32-byte little-endian Sapling IVK scalar from [`SaplingDiversifiableFvk::ivk_bytes`].
/// - `registry`: address → session_id map shared with the main chat loop.
/// - `conf_tx`: channel for delivering [`ConfirmationEvent`]s to the main loop.
/// - `lwd_endpoints`: lightwalletd URLs to try in order.
/// - `shutdown_rx`: send `true` to stop the watcher gracefully.
///
/// # Key material
///
/// `ivk_bytes` is key material.  This function never logs it.  The constructed
/// [`SaplingIvkDecryptor`] also holds no `Debug` impl.
pub fn spawn_block_watcher(
    ivk_bytes: [u8; 32],
    registry: Arc<AddressWatchRegistry>,
    conf_tx: mpsc::Sender<ConfirmationEvent>,
    lwd_endpoints: Vec<String>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;
    tokio::spawn(async move {
        // nie-hll: pending confirmation map: txid → (session_id, found_at_height).
        let mut pending: HashMap<String, (Uuid, u64)> = HashMap::new();

        let decryptor = match SaplingIvkDecryptor::new(&ivk_bytes) {
            Some(d) => d,
            None => {
                warn!("watcher: IVK bytes do not represent a valid scalar; watcher disabled");
                return;
            }
        };

        // Convert owned endpoint strings to refs once; used for all connect_with_failover calls.
        let lwd_refs: Vec<&str> = lwd_endpoints.iter().map(String::as_str).collect();

        // Connect to lightwalletd.  Try endpoints in order.
        let mut client = match nie_wallet::client::connect_with_failover(&lwd_refs).await {
            Ok(c) => c,
            Err(e) => {
                warn!("watcher: initial connect failed: {e}; watcher disabled");
                return;
            }
        };

        let poll_interval = Duration::from_secs(75);
        let mut backoff = Duration::from_secs(1);
        let mut scan_tip: u64 = 0;

        loop {
            // Shutdown check at top of each iteration.
            if *shutdown_rx.borrow() {
                info!("watcher: shutdown signal received");
                break;
            }

            // Fetch chain tip.
            let chain_tip = match client.latest_height().await {
                Ok(h) => h,
                Err(e) => {
                    warn!("watcher: latest_height failed ({e}); backoff {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    // Attempt reconnect on persistent failure.
                    if let Ok(c) = nie_wallet::client::connect_with_failover(&lwd_refs).await {
                        client = c;
                    }
                    continue;
                }
            };
            backoff = Duration::from_secs(1); // reset on success

            if scan_tip == 0 {
                // First poll: start one block behind the tip to catch any note in the
                // most recent block.
                scan_tip = chain_tip.saturating_sub(1);
            }

            // Scan new blocks.
            if scan_tip < chain_tip {
                match client.get_block_range(scan_tip + 1, chain_tip).await {
                    Ok(mut stream) => {
                        while let Ok(Some(block)) = stream.message().await {
                            let block_height = block.height;

                            // nie-ghf: trial-decrypt every Sapling output.
                            for tx in &block.vtx {
                                // Canonical txid: reverse LE hash bytes → hex.
                                if tx.hash.len() != 32 {
                                    continue; // malformed proto; skip
                                }
                                let mut txid_bytes = [0u8; 32];
                                txid_bytes.copy_from_slice(&tx.hash);
                                txid_bytes.reverse();
                                let txid: String =
                                    txid_bytes.iter().map(|b| format!("{b:02x}")).collect();

                                for (idx, output) in tx.outputs.iter().enumerate() {
                                    if let Some(note) = decryptor.try_decrypt_sapling(
                                        block_height,
                                        block.time,
                                        &tx.hash,
                                        idx,
                                        output,
                                    ) {
                                        // Derive the Sapling address key from the decrypted note.
                                        // PaymentAddress bytes layout: [diversifier(11) | pk_d(32)] = 43 bytes.
                                        // The scanner stores these split across note_diversifier and note_pk_d.
                                        let note_d: Option<&[u8]> =
                                            note.note_diversifier.as_deref();
                                        let note_pkd: Option<&[u8]> = note.note_pk_d.as_deref();
                                        if let (Some(d), Some(pkd)) = (note_d, note_pkd) {
                                            if d.len() == 11 && pkd.len() == 32 {
                                                let mut addr_bytes = [0u8; 43];
                                                addr_bytes[..11].copy_from_slice(d);
                                                addr_bytes[11..].copy_from_slice(pkd);
                                                let addr_key: String = addr_bytes
                                                    .iter()
                                                    .map(|b| format!("{b:02x}"))
                                                    .collect();

                                                if let Some(session_id) = registry.lookup(&addr_key)
                                                {
                                                    // nie-hll: record in pending map (dedup).
                                                    pending
                                                        .entry(txid.clone())
                                                        .or_insert((session_id, block_height));
                                                    info!(
                                                        session_id = %session_id,
                                                        txid = %txid,
                                                        height = block_height,
                                                        "watcher: payment detected"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // nie-hll: check depth for all pending entries at this block.
                            let mut confirmed: Vec<(String, Uuid, u64)> = Vec::new();
                            for (txid, (session_id, found_height)) in &pending {
                                if block_height < *found_height {
                                    // Should not happen; skip silently (chain reorg guard).
                                    warn!(
                                        txid = %txid,
                                        block_height,
                                        found_height,
                                        "watcher: block_height < found_height (reorg?); skipping depth check"
                                    );
                                    continue;
                                }
                                let depth = block_height - found_height;
                                if depth >= MIN_CONFIRMATIONS {
                                    confirmed.push((txid.clone(), *session_id, *found_height));
                                }
                            }
                            for (txid, session_id, found_height) in confirmed {
                                pending.remove(&txid);
                                let event = ConfirmationEvent {
                                    session_id,
                                    txid,
                                    block_height: found_height,
                                };
                                // If the main loop has exited, treat as shutdown.
                                if conf_tx.send(event).await.is_err() {
                                    info!("watcher: conf_tx closed; shutting down");
                                    return;
                                }
                            }

                            scan_tip = block_height;
                        }
                    }
                    Err(e) => {
                        warn!("watcher: get_block_range failed: {e}");
                    }
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt a known 64-byte keyfile blob, decrypt it back, verify the exact bytes
    /// are recovered. Wrong-passphrase and corrupt-ciphertext cases prove the
    /// encryption is real AEAD, not just a no-op or XOR with a constant.
    #[test]
    fn keyfile_encrypt_decrypt_roundtrip() {
        // Fixed 64-byte blob (Ed25519_seed || X25519_seed) — external test data,
        // not derived from the functions under test.
        let seed: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_add(0x01));
        let passphrase = "correct-horse-battery-staple";

        let ciphertext = encrypt_keyfile(&seed, passphrase).expect("encrypt must succeed");
        let recovered = decrypt_keyfile(&ciphertext, passphrase).expect("decrypt must succeed");
        assert_eq!(recovered, seed);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let seed = [0xabu8; 64];
        let ciphertext = encrypt_keyfile(&seed, "right-pass").expect("encrypt must succeed");
        let result = decrypt_keyfile(&ciphertext, "wrong-pass");
        assert!(result.is_err(), "wrong passphrase must be rejected");
    }

    #[test]
    fn corrupt_ciphertext_rejected() {
        let seed = [0xcdu8; 64];
        let mut ciphertext = encrypt_keyfile(&seed, "test-pass").expect("encrypt must succeed");
        // Flip a byte in the middle of the ciphertext to break the AEAD tag.
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xff;
        let result = decrypt_keyfile(&ciphertext, "test-pass");
        assert!(result.is_err(), "corrupt ciphertext must be rejected");
    }

    #[test]
    fn wallet_key_encrypt_decrypt_roundtrip() {
        // Fixed 64-byte key — external test data, not derived from functions under test.
        let key_bytes: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_add(0x10));
        let passphrase = "horse-battery-staple-correct";
        let ciphertext = encrypt_wallet_key(&key_bytes, passphrase).expect("encrypt must succeed");
        let recovered = decrypt_wallet_key(&ciphertext, passphrase).expect("decrypt must succeed");
        assert_eq!(recovered, key_bytes);
    }

    #[test]
    fn wallet_key_wrong_passphrase_rejected() {
        let key_bytes = [0x42u8; 64];
        let ciphertext = encrypt_wallet_key(&key_bytes, "right").expect("encrypt must succeed");
        assert!(
            decrypt_wallet_key(&ciphertext, "wrong").is_err(),
            "wrong passphrase must be rejected"
        );
    }

    // ---- dispatch_payment tests ----

    /// Unknown session + non-Request action → Unknown response is broadcast.
    ///
    /// Oracle: the response message is independently verified via serde_json
    /// on the channel output — not by trusting dispatch_payment's own path.
    #[tokio::test]
    async fn dispatch_unknown_session_non_request_sends_unknown() {
        let mut sessions: HashMap<Uuid, PaymentSession> = HashMap::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session_id = Uuid::new_v4();
        let action = nie_core::messages::PaymentAction::Confirmed {
            tx_hash: "abc123".to_string(),
        };
        let mut mls = nie_core::mls::MlsClient::new("test-dispatch").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            action,
            "peer-pub-id",
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false, // mls_active = false → no encryption, raw bytes
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive, "channel must still be open");

        let sent = rx.try_recv().expect("Unknown response must have been sent");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };
        let msg: ClearMessage =
            serde_json::from_slice(&payload).expect("payload must be valid ClearMessage JSON");
        let ClearMessage::Payment {
            session_id: sid,
            action: nie_core::messages::PaymentAction::Unknown { reason },
        } = msg
        else {
            panic!("expected Payment::Unknown");
        };
        assert_eq!(sid, session_id, "session_id must be echoed back");
        assert!(
            reason.contains("session not found"),
            "reason must explain the failure, got: {reason}"
        );
    }

    /// Malformed amount in a Request → Unknown reply sent, no session created. (nie-dxb)
    ///
    /// Oracle: the channel output is decoded independently via serde_json; the sessions
    /// map is verified to remain empty confirming no session was created for a sub-dust amount.
    #[tokio::test]
    async fn dispatch_request_sub_dust_sends_unknown_no_session() {
        let mut sessions: HashMap<Uuid, PaymentSession> = HashMap::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session_id = Uuid::new_v4();
        let action = nie_core::messages::PaymentAction::Request {
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 1_000, // below DUST_THRESHOLD (10_000)
        };
        let mut mls = nie_core::mls::MlsClient::new("test-bad-amount").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            action,
            "peer-pub-id",
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive, "channel must still be open");
        assert!(
            sessions.is_empty(),
            "no session must be created for malformed amount"
        );

        let sent = rx.try_recv().expect("Unknown response must have been sent");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };
        let msg: ClearMessage = serde_json::from_slice(&payload).unwrap();
        let ClearMessage::Payment {
            action: nie_core::messages::PaymentAction::Unknown { reason },
            ..
        } = msg
        else {
            panic!("expected Payment::Unknown, got {msg:?}");
        };
        assert!(
            reason.contains("dust threshold"),
            "reason must mention dust threshold, got: {reason}"
        );
    }

    /// Helper: build WalletFvks from a zero seed on testnet (account 0).
    ///
    /// Uses a fixed zero seed so tests are deterministic.  Testnet to avoid
    /// any accidental confusion with real mainnet addresses in test output.
    fn test_wallet_fvks() -> WalletFvks {
        let seed = [0u8; 64];
        let sapling_sk = SaplingExtendedSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0);
        let orchard_sk = OrchardSpendingKey::from_seed(&seed, ZcashNetwork::Testnet, 0).unwrap();
        let dfvk = sapling_sk.to_dfvk();
        WalletFvks {
            network: ZcashNetwork::Testnet,
            sapling: dfvk,
            orchard: orchard_sk.to_fvk(),
            sapling_sk: Arc::new(sapling_sk),
        }
    }

    /// try_load_wallet_fvks produces the same FVKs as test_wallet_fvks for the same seed.
    ///
    /// Oracle: test_wallet_fvks() passes the raw BIP-39 seed to from_seed() directly;
    /// try_load_wallet_fvks reads wallet.key, decrypts it, then passes the bytes to
    /// from_seed().  If the stored bytes are the seed (correct), both paths agree.
    /// If the stored bytes were the ZIP-32 master key (old bug), they disagree —
    /// the Sapling default address bytes would differ.
    #[test]
    fn try_load_wallet_fvks_matches_direct_derivation() {
        let seed = [0u8; 64];
        let dir = tempfile::TempDir::new().unwrap();

        // Write wallet.key with the known zero seed, unencrypted (no-passphrase path).
        let ciphertext = encrypt_wallet_key(&seed, "").expect("encrypt must succeed");
        std::fs::write(dir.path().join("wallet.key"), &ciphertext).unwrap();

        // Write wallet.json with testnet network.
        WalletMeta {
            network: "testnet".to_owned(),
        }
        .save(dir.path())
        .expect("wallet.json write must succeed");

        // Load via try_load_wallet_fvks (the production path).
        let loaded = try_load_wallet_fvks(dir.path(), true /* no_passphrase */, "testnet")
            .expect("try_load_wallet_fvks must succeed for a valid wallet.key");

        // Compare the Sapling default address bytes against the direct-seed path.
        let expected = test_wallet_fvks();
        let (_, expected_addr) = expected
            .sapling
            .find_address(0)
            .expect("find_address(0) must succeed");
        let (_, loaded_addr) = loaded
            .sapling
            .find_address(0)
            .expect("find_address(0) must succeed");
        assert_eq!(
            loaded_addr.to_bytes(),
            expected_addr.to_bytes(),
            "try_load_wallet_fvks must produce the same Sapling FVK as direct seed derivation"
        );

        // Also compare Orchard default address bytes.
        let expected_orchard = expected.orchard.default_address().to_raw_address_bytes();
        let loaded_orchard = loaded.orchard.default_address().to_raw_address_bytes();
        assert_eq!(
            loaded_orchard, expected_orchard,
            "try_load_wallet_fvks must produce the same Orchard FVK as direct seed derivation"
        );
    }

    /// Unknown session + Request with wallet → payee creates session and replies with
    /// a real Sapling+Orchard Unified Address.
    ///
    /// Oracle: the returned address is a valid testnet bech32m UA (starts with
    /// "utest1") produced by the deterministic zero-seed derivation; the sessions
    /// map is verified to confirm a Payee session was created with AddressProvided state.
    #[tokio::test]
    async fn dispatch_request_creates_payee_session_and_sends_address() {
        let mut sessions: HashMap<Uuid, PaymentSession> = HashMap::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session_id = Uuid::new_v4();
        let action = nie_core::messages::PaymentAction::Request {
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000, // 0.001 ZEC
        };
        let mut mls = nie_core::mls::MlsClient::new("test-dispatch-req").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();
        store.ensure_account(PAYMENT_ACCOUNT).await.unwrap();
        let fvks = test_wallet_fvks();

        let alive = dispatch_payment(
            session_id,
            action,
            "peer-pub-id",
            &mut sessions,
            &store,
            Some(&fvks),
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false, // mls_active = false → raw bytes, no encryption
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive, "channel must still be open");

        // Session must be created with Payee role and AddressProvided state.
        let session = sessions
            .get(&session_id)
            .expect("payee session must be created");
        assert_eq!(session.role, nie_core::messages::PaymentRole::Payee);
        assert_eq!(
            session.state,
            nie_core::messages::PaymentState::AddressProvided
        );
        let addr = session.address.as_deref().expect("address must be set");
        // Testnet UA HRP is "utest"; bech32m encoding starts with "utest1".
        assert!(
            addr.starts_with("utest1"),
            "testnet UA must start with 'utest1', got: {addr}"
        );

        // An Address reply must have been sent (NOT Unknown).
        let sent = rx.try_recv().expect("Address response must have been sent");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };
        let msg: ClearMessage =
            serde_json::from_slice(&payload).expect("payload must be valid ClearMessage JSON");
        let ClearMessage::Payment {
            session_id: sid,
            action: nie_core::messages::PaymentAction::Address { address, .. },
        } = msg
        else {
            panic!("expected Payment::Address, got {msg:?}");
        };
        assert_eq!(sid, session_id, "session_id must be echoed back");
        assert!(
            address.starts_with("utest1"),
            "address in Address reply must be a testnet UA, got: {address}"
        );
    }

    /// Request with no wallet → Unknown reply, no session created, helpful message.
    ///
    /// Oracle: the channel emits PaymentAction::Unknown with "wallet not initialized"
    /// in the reason; the sessions map remains empty (no session created).
    #[tokio::test]
    async fn dispatch_request_no_wallet_sends_unknown() {
        let mut sessions: HashMap<Uuid, PaymentSession> = HashMap::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session_id = Uuid::new_v4();
        let action = nie_core::messages::PaymentAction::Request {
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000, // 0.001 ZEC
        };
        let mut mls = nie_core::mls::MlsClient::new("test-no-wallet").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            action,
            "peer-pub-id",
            &mut sessions,
            &store,
            None, // no wallet
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive, "channel must still be open");
        assert!(
            sessions.is_empty(),
            "no session must be created when wallet is absent"
        );

        let sent = rx.try_recv().expect("Unknown response must have been sent");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };
        let msg: ClearMessage = serde_json::from_slice(&payload).unwrap();
        let ClearMessage::Payment {
            action: nie_core::messages::PaymentAction::Unknown { reason },
            ..
        } = msg
        else {
            panic!("expected Payment::Unknown, got {msg:?}");
        };
        assert!(
            reason.contains("wallet not initialized"),
            "reason must explain wallet is absent, got: {reason}"
        );
    }

    /// Two consecutive payment requests produce distinct Unified Addresses.
    ///
    /// Oracle: the diversifier index is atomically incremented between calls so
    /// the two addresses are derived at different indices and must therefore differ.
    #[tokio::test]
    async fn dispatch_request_consecutive_addresses_differ() {
        let mut sessions: HashMap<Uuid, PaymentSession> = HashMap::new();
        let fvks = test_wallet_fvks();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();
        store.ensure_account(PAYMENT_ACCOUNT).await.unwrap();

        // First payment request.
        let (tx1, mut rx1) = tokio::sync::mpsc::channel(4);
        let sid1 = Uuid::new_v4();
        let mut mls1 = nie_core::mls::MlsClient::new("test-consec-1").unwrap();
        let alive = dispatch_payment(
            sid1,
            nie_core::messages::PaymentAction::Request {
                chain: nie_core::messages::Chain::Zcash,
                amount_zatoshi: 100_000, // 0.001 ZEC
            },
            "peer-a",
            &mut sessions,
            &store,
            Some(&fvks),
            &HashMap::new(),
            &HashMap::new(),
            &tx1,
            false,
            &mut mls1,
            None,
            None,
        )
        .await;
        assert!(alive, "first dispatch must not close channel");

        // Second payment request (different session, same wallet).
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(4);
        let sid2 = Uuid::new_v4();
        let mut mls2 = nie_core::mls::MlsClient::new("test-consec-2").unwrap();
        let alive = dispatch_payment(
            sid2,
            nie_core::messages::PaymentAction::Request {
                chain: nie_core::messages::Chain::Zcash,
                amount_zatoshi: 200_000, // 0.002 ZEC
            },
            "peer-b",
            &mut sessions,
            &store,
            Some(&fvks),
            &HashMap::new(),
            &HashMap::new(),
            &tx2,
            false,
            &mut mls2,
            None,
            None,
        )
        .await;
        assert!(alive, "second dispatch must not close channel");

        // Extract the two addresses from the channel broadcasts.
        fn extract_address(rx: &mut tokio::sync::mpsc::Receiver<JsonRpcRequest>) -> String {
            let sent = rx.try_recv().expect("address reply must have been sent");
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request"
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            let payload = p.payload;
            let msg: ClearMessage = serde_json::from_slice(&payload).unwrap();
            let ClearMessage::Payment {
                action: nie_core::messages::PaymentAction::Address { address, .. },
                ..
            } = msg
            else {
                panic!("expected Payment::Address, got {msg:?}");
            };
            address
        }

        let addr1 = extract_address(&mut rx1);
        let addr2 = extract_address(&mut rx2);

        assert_ne!(
            addr1, addr2,
            "consecutive payment requests must produce distinct addresses"
        );
    }

    /// Message from a third party (not the session peer) is silently dropped. (nie-2f8)
    ///
    /// Oracle: after dispatching a message from an unrelated pub_id, the channel
    /// is empty (no reply sent) and the session is not modified.
    #[tokio::test]
    async fn dispatch_occupied_ignores_non_party_sender() {
        let session_id = Uuid::new_v4();
        let peer_pub_id = "a".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 1_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-2f8").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        // Message arrives from a different peer — not peer_pub_id.
        let unrelated = "b".repeat(64);
        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Unknown {
                reason: "noise".into(),
            },
            &unrelated,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive, "channel must still be open");
        assert!(
            rx.try_recv().is_err(),
            "no reply must be sent for non-party sender"
        );
        // Session state must be unchanged.
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Requested
        );
    }

    /// Payer receives Address → state transitions to AddressProvided, no message sent. (nie-c20)
    ///
    /// Oracle: session state is read back from the in-memory map and verified to be
    /// AddressProvided.  The channel is checked empty (no reply from payer on Address).
    #[tokio::test]
    async fn dispatch_payer_receives_address_transitions_state() {
        let session_id = Uuid::new_v4();
        let peer_pub_id = "a".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-c20").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Address {
                chain: nie_core::messages::Chain::Zcash,
                address: "test-addr".to_string(),
            },
            &peer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive);
        assert!(rx.try_recv().is_err(), "payer must not reply to Address");
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::AddressProvided
        );
        assert_eq!(sessions[&session_id].address.as_deref(), Some("test-addr"));
    }

    /// Payee receives Sent → auto-sends Confirmed, state reaches Confirmed. (nie-6sp)
    ///
    /// Oracle: channel output is decoded via serde_json (not dispatch_payment's own
    /// serialization path) and confirmed to be PaymentAction::Confirmed.
    #[tokio::test]
    async fn dispatch_payee_receives_sent_sends_confirmed_and_transitions() {
        let session_id = Uuid::new_v4();
        let payer_pub_id = "c".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 50_000,
            peer_pub_id: payer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payee,
            state: nie_core::messages::PaymentState::AddressProvided,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: Some("stub-addr".to_string()),
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-6sp").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Sent {
                chain: nie_core::messages::Chain::Zcash,
                tx_hash: "txhash-abc".to_string(),
                amount_zatoshi: 50_000, // 0.0005 ZEC
            },
            &payer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive);
        // nie-iiy: payee transitions to Sent and waits for the block watcher; no
        // Confirmed message is sent immediately (the auto-confirm stub is removed).
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Sent
        );
        assert_eq!(sessions[&session_id].tx_hash.as_deref(), Some("txhash-abc"));
        assert!(
            rx.try_recv().is_err(),
            "no immediate Confirmed reply; watcher will fire it"
        );
    }

    /// Payee receives Unknown in AddressProvided → state transitions to Failed. (nie-6sp)
    #[tokio::test]
    async fn dispatch_payee_receives_unknown_transitions_to_failed() {
        let session_id = Uuid::new_v4();
        let payer_pub_id = "d".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 1_000,
            peer_pub_id: payer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payee,
            state: nie_core::messages::PaymentState::AddressProvided,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: Some("stub".to_string()),
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-6sp-fail").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Unknown {
                reason: "payer cancelled".to_string(),
            },
            &payer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Failed
        );
        assert!(rx.try_recv().is_err(), "no reply for Unknown on payee side");
    }

    /// Payer receives Confirmed in Sent state → state reaches Confirmed. (nie-c1v)
    #[tokio::test]
    async fn dispatch_payer_receives_confirmed_transitions_to_confirmed() {
        let session_id = Uuid::new_v4();
        let payee_pub_id = "e".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 1_000,
            peer_pub_id: payee_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Sent,
            created_at: now,
            updated_at: now,
            tx_hash: Some("txhash-sent".to_string()),
            address: Some("payee-addr".to_string()),
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-c1v-confirm").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        // Canonical Zcash txid: 64 lowercase hex chars (oracle: nie-iiy spec).
        let valid_txid = "a".repeat(64);
        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Confirmed {
                tx_hash: valid_txid.clone(),
            },
            &payee_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Confirmed
        );
        assert_eq!(
            sessions[&session_id].tx_hash.as_deref(),
            Some(valid_txid.as_str())
        );
        assert!(rx.try_recv().is_err(), "payer sends no reply to Confirmed");
    }

    /// Payer receives Unknown in any payer state → state reaches Failed. (nie-c1v)
    #[tokio::test]
    async fn dispatch_payer_receives_unknown_transitions_to_failed() {
        let session_id = Uuid::new_v4();
        let payee_pub_id = "f".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 1_000,
            peer_pub_id: payee_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-c1v-fail").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Unknown {
                reason: "payee lost session".to_string(),
            },
            &payee_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Failed
        );
        assert!(rx.try_recv().is_err(), "payer sends no reply to Unknown");
    }

    /// Peer sends Cancelled in any active state → local session transitions to Expired.
    /// No reply is sent back. (nie-0bj)
    ///
    /// Oracle: state observed directly on the sessions map; no reply on the channel.
    #[tokio::test]
    async fn dispatch_receives_cancelled_transitions_to_expired() {
        let session_id = Uuid::new_v4();
        let peer_pub_id = "a".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 1_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-cancelled").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Cancelled {
                reason: "payee changed mind".to_string(),
            },
            &peer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            None,
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Expired
        );
        assert!(rx.try_recv().is_err(), "no reply sent on Cancelled");
    }

    // ---- send_fn integration tests ----

    /// Payer auto-sends when send_fn returns Ok: state advances to Sent and
    /// PaymentAction::Sent is broadcast to the payee.
    ///
    /// Oracle: session state is read back from the in-memory map; the channel
    /// output is decoded independently via serde_json and verified to contain
    /// the expected txid.
    #[tokio::test]
    async fn payer_auto_sends_after_address_received() {
        let session_id = Uuid::new_v4();
        let peer_pub_id = "a".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-auto-send").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let mock_fn = |_addr: String,
                       _amt: u64,
                       _sid: Uuid|
         -> Pin<
            Box<dyn std::future::Future<Output = Result<String, SendPaymentError>> + Send>,
        > { Box::pin(async { Ok("deadbeef0000cafe".repeat(4)) }) };
        let sf: &SendFn = &mock_fn;

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Address {
                chain: nie_core::messages::Chain::Zcash,
                address: "utest1-recv-addr".to_string(),
            },
            &peer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            Some(sf),
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::Sent,
            "state must advance to Sent after successful broadcast"
        );
        assert_eq!(
            sessions[&session_id].tx_hash.as_deref(),
            Some("deadbeef0000cafe".repeat(4).as_str()),
            "tx_hash must be set from the send_fn result"
        );

        // Channel must carry a PaymentAction::Sent with the txid.
        let sent = rx.try_recv().expect("Sent message must be on channel");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };
        let msg: ClearMessage = serde_json::from_slice(&payload).unwrap();
        let ClearMessage::Payment {
            action: nie_core::messages::PaymentAction::Sent { tx_hash, .. },
            ..
        } = msg
        else {
            panic!("expected Payment::Sent, got {msg:?}");
        };
        assert_eq!(tx_hash, "deadbeef0000cafe".repeat(4));
    }

    /// Payer receives SyncLag from send_fn: stays in AddressProvided, no Sent
    /// broadcast, channel is empty.
    ///
    /// Oracle: session state and channel are observed independently after dispatch.
    #[tokio::test]
    async fn payer_sync_lag_stays_in_address_provided() {
        let session_id = Uuid::new_v4();
        let peer_pub_id = "b".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 50_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-sync-lag").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let lag_fn = |_: String,
                      _: u64,
                      _: Uuid|
         -> Pin<
            Box<dyn std::future::Future<Output = Result<String, SendPaymentError>> + Send>,
        > {
            Box::pin(async {
                Err(SendPaymentError::SyncLag(
                    nie_wallet::sync_guard::SyncLagError {
                        scan_tip: 10,
                        chain_tip: 100,
                    },
                ))
            })
        };
        let sf: &SendFn = &lag_fn;

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Address {
                chain: nie_core::messages::Chain::Zcash,
                address: "utest1-recv-addr".to_string(),
            },
            &peer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            Some(sf),
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::AddressProvided,
            "SyncLag must leave state in AddressProvided"
        );
        assert!(
            sessions[&session_id].tx_hash.is_none(),
            "tx_hash must remain None on SyncLag"
        );
        assert!(
            rx.try_recv().is_err(),
            "SyncLag must not broadcast Sent or Unknown"
        );
    }

    /// Payer receives InsufficientFunds from send_fn: stays in AddressProvided,
    /// no broadcast sent.
    ///
    /// Oracle: session state and channel verified independently after dispatch.
    #[tokio::test]
    async fn payer_insufficient_funds_stays_in_address_provided() {
        let session_id = Uuid::new_v4();
        let peer_pub_id = "c".repeat(64);
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 9_999_999_999,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Requested,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: None,
        };
        let mut sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut mls = nie_core::mls::MlsClient::new("test-insuf-funds").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = WalletStore::new(tmp.path()).await.unwrap();

        let insuf_fn = |_: String,
                        _: u64,
                        _: Uuid|
         -> Pin<
            Box<dyn std::future::Future<Output = Result<String, SendPaymentError>> + Send>,
        > {
            Box::pin(async {
                Err(SendPaymentError::Build(
                    nie_wallet::tx_error::TxBuildError::InsufficientFunds {
                        have: 1_000,
                        need: 9_999_999_999,
                    },
                ))
            })
        };
        let sf: &SendFn = &insuf_fn;

        let alive = dispatch_payment(
            session_id,
            nie_core::messages::PaymentAction::Address {
                chain: nie_core::messages::Chain::Zcash,
                address: "utest1-recv-addr".to_string(),
            },
            &peer_pub_id,
            &mut sessions,
            &store,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &tx,
            false,
            &mut mls,
            Some(sf),
            None,
        )
        .await;

        assert!(alive);
        assert_eq!(
            sessions[&session_id].state,
            nie_core::messages::PaymentState::AddressProvided,
            "InsufficientFunds must leave state in AddressProvided"
        );
        assert!(
            sessions[&session_id].tx_hash.is_none(),
            "tx_hash must remain None on InsufficientFunds"
        );
        assert!(
            rx.try_recv().is_err(),
            "InsufficientFunds must not broadcast Sent or Unknown"
        );
    }

    // ---- send_payment_message MLS-active path tests ----

    /// MLS-active path: payload sent to channel is MLS ciphertext that decrypts
    /// to the original ClearMessage::Payment.
    ///
    /// Oracle: Bob (group member) decrypts the channel output with
    /// process_incoming() and the result is independently verified via
    /// serde_json — not by trusting send_payment_message's own serialize path.
    #[tokio::test]
    async fn send_payment_message_mls_active_payload_decryptable() {
        let mut alice = nie_core::mls::MlsClient::new("alice-pay-send").unwrap();
        let mut bob = nie_core::mls::MlsClient::new("bob-pay-recv").unwrap();

        alice.create_group().unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();
        let (_, welcome) = alice.add_member(&bob_kp).unwrap();
        bob.join_from_welcome(&welcome).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session_id = Uuid::new_v4();
        let action = nie_core::messages::PaymentAction::Request {
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000, // 0.001 ZEC
        };

        let alive = send_payment_message(session_id, action, &tx, true, &mut alice).await;
        assert!(
            alive,
            "channel must still be open after successful MLS send"
        );

        let sent = rx
            .try_recv()
            .expect("encrypted payment message must be sent");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };

        // payload must be MLS ciphertext, not raw JSON — serde_json must reject it.
        assert!(
            serde_json::from_slice::<ClearMessage>(&payload).is_err(),
            "MLS-active payload must not be raw JSON (must be opaque ciphertext)"
        );

        // Bob decrypts; oracle: unpad then process_incoming returns the original plaintext.
        let ciphertext =
            nie_core::messages::unpad(&payload).expect("payload must be padded ciphertext");
        let plaintext = bob
            .process_incoming(&ciphertext)
            .expect("Bob must process MLS message without error")
            .expect("must be an application message, not a commit");

        let msg: ClearMessage = serde_json::from_slice(&plaintext)
            .expect("decrypted bytes must be valid ClearMessage JSON");
        let ClearMessage::Payment {
            session_id: sid,
            action: decoded,
        } = msg
        else {
            panic!("expected Payment, got {msg:?}");
        };
        assert_eq!(sid, session_id, "session_id must survive MLS roundtrip");
        assert!(
            matches!(decoded, nie_core::messages::PaymentAction::Request { .. }),
            "action variant must survive MLS roundtrip"
        );
    }

    /// MLS-active path: if the MLS client has no group (e.g. group not yet
    /// established), encrypt() returns Err and send_payment_message must NOT
    /// send any message to the channel — falling back to plaintext is forbidden
    /// for payment messages.
    ///
    /// Oracle: the channel is empty after the call (try_recv returns Err).
    #[tokio::test]
    async fn send_payment_message_mls_no_group_does_not_send() {
        // MlsClient with no group — has_group() = false.
        let mut mls = nie_core::mls::MlsClient::new("no-group").unwrap();
        assert!(!mls.has_group(), "precondition: no group");

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session_id = Uuid::new_v4();
        let action = nie_core::messages::PaymentAction::Request {
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000_000, // 1.0 ZEC
        };

        let alive = send_payment_message(session_id, action, &tx, true, &mut mls).await;

        assert!(
            alive,
            "channel must still be alive after encryption failure"
        );
        assert!(
            rx.try_recv().is_err(),
            "no message must be sent when MLS encryption fails — plaintext fallback is forbidden"
        );
    }

    // ---- resync_sessions tests ----

    /// Payer/Sent session with a tx_hash retransmits PaymentAction::Sent on reconnect.
    ///
    /// Oracle: Bob (group member) decrypts the channel output with process_incoming()
    /// and independently verifies the action variant and tx_hash field — not by
    /// trusting resync_sessions' own serialize path.
    #[tokio::test]
    async fn resync_payer_sent_retransmits_sent_action() {
        let mut alice = nie_core::mls::MlsClient::new("alice-resync-sent").unwrap();
        let mut bob = nie_core::mls::MlsClient::new("bob-resync-sent").unwrap();

        alice.create_group().unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();
        let (_, welcome) = alice.add_member(&bob_kp).unwrap();
        bob.join_from_welcome(&welcome).unwrap();

        let peer_pub_id = "c".repeat(64);
        let session_id = Uuid::new_v4();
        let now = 1_000_000i64;
        let stored_tx_hash = "deadbeef".repeat(8); // 64 hex chars
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 500_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Sent,
            created_at: now,
            updated_at: now,
            tx_hash: Some(stored_tx_hash.clone()),
            address: Some("zs1payeeaddr".to_string()),
        };
        let sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let online = vec![peer_pub_id.clone()];

        let alive = resync_sessions(&sessions, &online, &tx, &mut alice).await;
        assert!(alive, "channel must still be open after resync");

        let sent = rx
            .try_recv()
            .expect("resync must send a message for Payer/Sent session");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };

        // Decrypt with Bob to get the plaintext — independent of Alice's serialize path.
        let ciphertext =
            nie_core::messages::unpad(&payload).expect("payload must be padded ciphertext");
        let plaintext = bob
            .process_incoming(&ciphertext)
            .expect("Bob must process MLS message")
            .expect("must be an application message");
        let msg: ClearMessage =
            serde_json::from_slice(&plaintext).expect("plaintext must be valid ClearMessage JSON");
        let ClearMessage::Payment {
            session_id: sid,
            action:
                nie_core::messages::PaymentAction::Sent {
                    tx_hash,
                    amount_zatoshi,
                    ..
                },
        } = msg
        else {
            panic!("expected Payment::Sent, got {msg:?}");
        };
        assert_eq!(sid, session_id, "session_id must survive resync");
        assert_eq!(tx_hash, stored_tx_hash, "tx_hash must match stored value");
        assert_eq!(
            amount_zatoshi, 500_000,
            "amount_zatoshi must match stored session value"
        );
    }

    /// Payer/Sent session with a missing tx_hash is skipped (defensive guard).
    ///
    /// Oracle: the channel is empty after resync — no Broadcast sent for the
    /// malformed session.  The function still returns true (channel open).
    #[tokio::test]
    async fn resync_payer_sent_no_tx_hash_is_skipped() {
        let peer_pub_id = "d".repeat(64);
        let session_id = Uuid::new_v4();
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::Sent,
            created_at: now,
            updated_at: now,
            tx_hash: None, // missing — should be skipped
            address: None,
        };
        let sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let online = vec![peer_pub_id.clone()];
        let mut mls = nie_core::mls::MlsClient::new("resync-no-hash").unwrap();

        let alive = resync_sessions(&sessions, &online, &tx, &mut mls).await;
        assert!(alive, "channel must still be open");
        assert!(
            rx.try_recv().is_err(),
            "malformed Payer/Sent session must not send any message"
        );
    }

    /// Payee/Sent session retransmits PaymentAction::Confirmed on reconnect.
    ///
    /// Crash-recovery scenario: payee receives Sent, DB upserts Payee/Sent,
    /// then the process crashes before Confirmed is broadcast.  On restart,
    /// resync_sessions must retransmit Confirmed so the payer can complete.
    ///
    /// Oracle: Bob decrypts the channel output with process_incoming() and
    /// independently verifies the Confirmed variant and tx_hash — not by
    /// trusting resync_sessions' own serialize path.
    #[tokio::test]
    async fn resync_payee_sent_retransmits_confirmed_action() {
        let mut alice = nie_core::mls::MlsClient::new("alice-resync-confirmed").unwrap();
        let mut bob = nie_core::mls::MlsClient::new("bob-resync-confirmed").unwrap();

        alice.create_group().unwrap();
        let bob_kp = bob.key_package_bytes().unwrap();
        let (_, welcome) = alice.add_member(&bob_kp).unwrap();
        bob.join_from_welcome(&welcome).unwrap();

        let peer_pub_id = "e".repeat(64);
        let session_id = Uuid::new_v4();
        let now = 1_000_000i64;
        let stored_tx_hash = "cafebabe".repeat(8); // 64 hex chars
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 200_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payee,
            state: nie_core::messages::PaymentState::Sent,
            created_at: now,
            updated_at: now,
            tx_hash: Some(stored_tx_hash.clone()),
            address: Some("zs1payeraddr".to_string()),
        };
        let sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let online = vec![peer_pub_id.clone()];

        let alive = resync_sessions(&sessions, &online, &tx, &mut alice).await;
        assert!(alive, "channel must still be open after resync");

        let sent = rx
            .try_recv()
            .expect("resync must send a message for Payee/Sent session");
        let payload = {
            assert_eq!(
                sent.method,
                rpc_methods::BROADCAST,
                "expected broadcast request, got method: {}",
                sent.method
            );
            let p: BroadcastParams =
                serde_json::from_value(sent.params.expect("broadcast must have params")).unwrap();
            p.payload
        };

        // Decrypt with Bob — independent of Alice's serialize path.
        let ciphertext =
            nie_core::messages::unpad(&payload).expect("payload must be padded ciphertext");
        let plaintext = bob
            .process_incoming(&ciphertext)
            .expect("Bob must process MLS message")
            .expect("must be an application message");
        let msg: ClearMessage =
            serde_json::from_slice(&plaintext).expect("plaintext must be valid ClearMessage JSON");
        let ClearMessage::Payment {
            session_id: sid,
            action: nie_core::messages::PaymentAction::Confirmed { tx_hash },
        } = msg
        else {
            panic!("expected Payment::Confirmed, got {msg:?}");
        };
        assert_eq!(sid, session_id, "session_id must survive resync");
        assert_eq!(tx_hash, stored_tx_hash, "tx_hash must match stored value");
    }

    /// Payer/AddressProvided session sends no peer message on resync — the payer
    /// already has the address stored; only a local reminder is printed.
    ///
    /// Oracle: channel is empty after resync (no Broadcast), and the function
    /// returns true (channel still open).  The println! side effect is not
    /// captured but the absence of a channel message is the key invariant.
    #[tokio::test]
    async fn resync_payer_address_provided_sends_no_message() {
        let peer_pub_id = "b".repeat(64);
        let session_id = Uuid::new_v4();
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 300_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payer,
            state: nie_core::messages::PaymentState::AddressProvided,
            created_at: now,
            updated_at: now,
            tx_hash: None,
            address: Some("zs1someaddr".to_string()),
        };
        let sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let online = vec![peer_pub_id.clone()];
        let mut mls = nie_core::mls::MlsClient::new("resync-addr-provided").unwrap();

        let alive = resync_sessions(&sessions, &online, &tx, &mut mls).await;
        assert!(alive, "channel must still be open");
        assert!(
            rx.try_recv().is_err(),
            "Payer/AddressProvided must not send a peer message — address is already stored locally"
        );
    }

    /// Payee/Sent session with a missing tx_hash is skipped (defensive guard).
    ///
    /// Oracle: the channel is empty after resync — no Broadcast sent for the
    /// malformed session.  The function still returns true (channel open).
    #[tokio::test]
    async fn resync_payee_sent_no_tx_hash_is_skipped() {
        let peer_pub_id = "f".repeat(64);
        let session_id = Uuid::new_v4();
        let now = 1_000_000i64;
        let session = PaymentSession {
            id: session_id,
            chain: nie_core::messages::Chain::Zcash,
            amount_zatoshi: 100_000,
            peer_pub_id: peer_pub_id.clone(),
            role: nie_core::messages::PaymentRole::Payee,
            state: nie_core::messages::PaymentState::Sent,
            created_at: now,
            updated_at: now,
            tx_hash: None, // corrupt DB row — should be skipped
            address: None,
        };
        let sessions = HashMap::from([(session_id, session)]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let online = vec![peer_pub_id.clone()];
        let mut mls = nie_core::mls::MlsClient::new("resync-payee-no-hash").unwrap();

        let alive = resync_sessions(&sessions, &online, &tx, &mut mls).await;
        assert!(alive, "channel must still be open");
        assert!(
            rx.try_recv().is_err(),
            "Payee/Sent session with no tx_hash must not send any message"
        );
    }

    // ---- resolve_handle tests ----

    #[test]
    fn resolve_by_exact_pub_id() {
        let online = vec!["aabb".repeat(16)]; // 64-char pub_id
        let target = online[0].clone();
        let nicks = HashMap::new();
        let local = HashMap::new();
        assert_eq!(
            resolve_handle(&target, &online, &nicks, &local).unwrap(),
            target
        );
    }

    #[test]
    fn resolve_by_nickname_case_insensitive() {
        let pub_id = "cc".repeat(32);
        let online = vec![pub_id.clone()];
        let mut nicks = HashMap::new();
        nicks.insert(pub_id.clone(), "Alice".to_string());
        let local = HashMap::new();
        assert_eq!(
            resolve_handle("alice", &online, &nicks, &local).unwrap(),
            pub_id
        );
    }

    #[test]
    fn resolve_unknown_handle_errors() {
        let online: Vec<String> = vec![];
        let nicks = HashMap::new();
        let local = HashMap::new();
        assert!(resolve_handle("nobody", &online, &nicks, &local).is_err());
    }

    // ---- display_name tests ----
    // Oracle: expected values derived from the function specification:
    //   - PubId::short() returns first 8 chars + "\u{2026}" when len > 8, else the full string
    //   - nicknames take precedence over local_names (or_else order in source)
    //   - format when a name exists: "{name} ({short})"
    //   - format when no name exists: "{short}" only

    #[test]
    fn display_name_with_nickname() {
        // pub_id is 64 hex chars; short() = first 8 chars + U+2026 HORIZONTAL ELLIPSIS
        let pub_id = "aa".repeat(32); // 64-char string
        let mut nicknames = HashMap::new();
        nicknames.insert(pub_id.clone(), "Alice".to_string());
        let local_names = HashMap::new();

        let result = display_name(&pub_id, &nicknames, &local_names);

        // Oracle: nickname "Alice", short_id = "aaaaaaaa\u{2026}"
        assert_eq!(result, "Alice (aaaaaaaa\u{2026})");
    }

    #[test]
    fn display_name_nickname_preferred_over_local_alias() {
        // Both maps have an entry for the same pub_id.
        // Oracle: nicknames is checked first (.get().or_else()), so it wins.
        let pub_id = "bb".repeat(32);
        let mut nicknames = HashMap::new();
        nicknames.insert(pub_id.clone(), "ServerNick".to_string());
        let mut local_names = HashMap::new();
        local_names.insert(pub_id.clone(), "LocalAlias".to_string());

        let result = display_name(&pub_id, &nicknames, &local_names);

        // Oracle: "ServerNick" wins; short = "bbbbbbbb\u{2026}"
        assert_eq!(result, "ServerNick (bbbbbbbb\u{2026})");
    }

    #[test]
    fn display_name_fallback_to_short_id() {
        // Neither map has an entry for this pub_id -> short id only.
        let pub_id = "cc".repeat(32); // 64 hex chars
        let nicknames = HashMap::new();
        let local_names = HashMap::new();

        let result = display_name(&pub_id, &nicknames, &local_names);

        // Oracle: no name found; result is first 8 chars + U+2026
        assert_eq!(result, "cccccccc\u{2026}");
    }

    #[test]
    fn display_name_short_pub_id() {
        // pub_id shorter than 8 chars -> PubId::short() returns full string, no ellipsis, no panic.
        let pub_id = "abc1234"; // 7 chars, below the 8-char threshold
        let nicknames = HashMap::new();
        let local_names = HashMap::new();

        let result = display_name(pub_id, &nicknames, &local_names);

        // Oracle: short() returns the full 7-char string unchanged
        assert_eq!(result, "abc1234");
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn register_and_lookup_hit() {
        let reg = AddressWatchRegistry::new();
        let id = Uuid::new_v4();
        reg.register("addr1".to_string(), id);
        assert_eq!(reg.lookup("addr1"), Some(id));
    }

    #[test]
    fn lookup_miss_returns_none() {
        let reg = AddressWatchRegistry::new();
        assert_eq!(reg.lookup("notregistered"), None);
    }

    #[test]
    fn deregister_removes_entry() {
        let reg = AddressWatchRegistry::new();
        let id = Uuid::new_v4();
        reg.register("addr1".to_string(), id);
        reg.deregister("addr1");
        assert_eq!(reg.lookup("addr1"), None);
    }

    #[test]
    fn deregister_unknown_is_noop() {
        let reg = AddressWatchRegistry::new();
        reg.deregister("never_registered"); // must not panic
    }

    #[test]
    fn register_overwrites_same_address() {
        let reg = AddressWatchRegistry::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        reg.register("addr1".to_string(), id1);
        reg.register("addr1".to_string(), id2);
        assert_eq!(reg.lookup("addr1"), Some(id2));
    }

    #[test]
    fn len_and_is_empty() {
        let reg = AddressWatchRegistry::new();
        assert!(reg.is_empty());
        reg.register("a".to_string(), Uuid::new_v4());
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }
}

#[cfg(test)]
mod watcher_tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use uuid::Uuid;

    // ---- Test 1: min_confirmations_const ----
    //
    // Oracle: nie-ghf spec requires MIN_CONFIRMATIONS = 10.
    // The constant must exist at module scope in the watcher module.
    #[test]
    fn min_confirmations_const() {
        use super::MIN_CONFIRMATIONS;
        assert_eq!(
            MIN_CONFIRMATIONS, 10u64,
            "MIN_CONFIRMATIONS must be 10 per nie-ghf spec"
        );
    }

    // ---- Helper: depth-check step ----
    //
    // Mirrors the logic the watcher implementation will use: iterate pending,
    // fire on depth >= MIN_CONFIRMATIONS, remove from map.
    //
    // pending: txid -> (session_id, found_height)
    // Returns the list of (txid, session_id, found_height) entries that fired.
    fn check_depth(
        pending: &mut HashMap<String, (Uuid, u64)>,
        current_height: u64,
        threshold: u64,
    ) -> Vec<(String, Uuid, u64)> {
        let mut fired = Vec::new();
        let keys: Vec<String> = pending.keys().cloned().collect();
        for txid in keys {
            if let Some(&(session_id, found_height)) = pending.get(&txid) {
                let depth = current_height.saturating_sub(found_height);
                if depth >= threshold {
                    fired.push((txid.clone(), session_id, found_height));
                    pending.remove(&txid);
                }
            }
        }
        fired
    }

    // ---- Test 2: depth_fires_at_threshold ----
    //
    // Oracle: depth = current_height - found_height; threshold = 10.
    // At depth 9 (height 109) no event fires.
    // At depth 10 (height 110) the event fires and the entry is removed.
    #[test]
    fn depth_fires_at_threshold() {
        let mut pending: HashMap<String, (Uuid, u64)> = HashMap::new();
        let session_id = Uuid::new_v4();
        let found_height = 100u64;
        pending.insert("abc".to_string(), (session_id, found_height));

        // depth = 109 - 100 = 9: below threshold, no fire
        let fired = check_depth(&mut pending, 109, 10);
        assert!(
            fired.is_empty(),
            "depth 9 is below threshold 10; no event should fire"
        );
        assert!(
            pending.contains_key("abc"),
            "entry must remain in pending when depth < threshold"
        );

        // depth = 110 - 100 = 10: at threshold, fires
        let fired = check_depth(&mut pending, 110, 10);
        assert_eq!(fired.len(), 1, "exactly one event must fire at depth 10");
        let (txid, sid, fh) = &fired[0];
        assert_eq!(txid, "abc");
        assert_eq!(*sid, session_id);
        assert_eq!(*fh, found_height);

        // Entry must be removed from pending
        assert!(
            !pending.contains_key("abc"),
            "entry must be removed from pending after event fires"
        );
    }

    // ---- Test 3: depth_no_duplicate_fire ----
    //
    // Oracle: HashMap::remove prevents re-entry; advancing height after removal
    // produces no further events for the same txid.
    #[test]
    fn depth_no_duplicate_fire() {
        let mut pending: HashMap<String, (Uuid, u64)> = HashMap::new();
        let session_id = Uuid::new_v4();
        pending.insert("abc".to_string(), (session_id, 100u64));

        // Fire once at height 110 (depth 10).
        let fired = check_depth(&mut pending, 110, 10);
        assert_eq!(fired.len(), 1, "first check at depth 10 must fire once");

        // Advance to height 120 — entry is already gone, must not fire again.
        let fired = check_depth(&mut pending, 120, 10);
        assert!(
            fired.is_empty(),
            "advancing height after entry removal must not fire again"
        );
    }

    // ---- Test 4: txid_reversal_in_watcher ----
    //
    // The txid stored and displayed must be the reverse-byte-order hex of the
    // raw CompactTx.hash bytes (little-endian on-wire → big-endian display).
    //
    // Oracle: manual computation.
    // Input: [0x01, 0x02, ..., 0x20] (32 bytes, values 1 through 32).
    // Reversed: [0x20, 0x1f, 0x1e, ..., 0x02, 0x01].
    // Expected hex: "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
    //
    // This mirrors scanner.rs txid_canonical_form but is written independently
    // for the watcher's implementation.
    fn txid_from_hash_bytes(hash: &[u8]) -> String {
        let mut reversed = hash.to_vec();
        reversed.reverse();
        reversed.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn txid_reversal_in_watcher() {
        let hash: Vec<u8> = (0x01u8..=0x20u8).collect();
        assert_eq!(hash.len(), 32, "input must be 32 bytes");

        let expected = "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201";
        let got = txid_from_hash_bytes(&hash);
        assert_eq!(
            got, expected,
            "watcher txid must be reverse-byte-order hex of CompactTx.hash"
        );
    }

    // ---- Test 5: backoff_cap ----
    //
    // The exponential backoff doubles on each failure but caps at 60 seconds.
    //
    // Oracle: 2^5 = 32 < 60, 2^6 = 64 > 60 → cap applies after 6 doublings.
    // Doubling sequence starting from 1s:
    //   1s → 2s → 4s → 8s → 16s → 32s → 60s (capped from 64s) → 60s
    fn apply_backoff(current: Duration) -> Duration {
        (current * 2).min(Duration::from_secs(60))
    }

    #[test]
    fn backoff_cap() {
        // Verify the doubling sequence up to and past the cap.
        assert_eq!(
            apply_backoff(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(
            apply_backoff(Duration::from_secs(2)),
            Duration::from_secs(4)
        );
        assert_eq!(
            apply_backoff(Duration::from_secs(4)),
            Duration::from_secs(8)
        );
        assert_eq!(
            apply_backoff(Duration::from_secs(8)),
            Duration::from_secs(16)
        );
        assert_eq!(
            apply_backoff(Duration::from_secs(16)),
            Duration::from_secs(32)
        );
        // 32 * 2 = 64 > 60 → cap at 60
        assert_eq!(
            apply_backoff(Duration::from_secs(32)),
            Duration::from_secs(60),
            "doubling 32s must cap at 60s"
        );
        // 60 * 2 = 120 > 60 → stays at 60
        assert_eq!(
            apply_backoff(Duration::from_secs(60)),
            Duration::from_secs(60),
            "already-capped value must remain at 60s"
        );
    }
}

// ---- nie-iiy: Confirmed message format and tx_hash validation ----
#[cfg(test)]
mod iiy_tests {
    use std::collections::HashMap;

    use nie_core::messages::PaymentSession;
    use nie_wallet::db::WalletStore;
    use uuid::Uuid;

    use super::*;

    /// PaymentAction::Confirmed serializes to the expected JSON.
    /// Oracle: manually constructed serde_json output; independent of dispatch_payment.
    #[test]
    fn test_confirmed_message_format() {
        let session_id = Uuid::nil();
        let tx_hash = "b".repeat(64);
        let msg = ClearMessage::Payment {
            session_id,
            action: nie_core::messages::PaymentAction::Confirmed {
                tx_hash: tx_hash.clone(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            json.contains("\"action\":\"confirmed\""),
            "tag must be 'confirmed'"
        );
        assert!(json.contains(&tx_hash), "tx_hash must appear in payload");
        assert_eq!(tx_hash.len(), 64, "test oracle: tx_hash is 64 chars");
    }

    /// Payer rejects a Confirmed with a non-hex or wrong-length tx_hash.
    /// Oracle: nie-iiy spec — 64 lowercase hex chars required; anything else rejected.
    #[tokio::test]
    async fn test_txhash_validation() {
        let session_id = Uuid::new_v4();
        let payee_pub_id = "f".repeat(64);

        async fn try_confirm(session_id: Uuid, payee_pub_id: &str, tx_hash: &str) -> bool {
            let session = PaymentSession {
                id: session_id,
                chain: nie_core::messages::Chain::Zcash,
                amount_zatoshi: 1_000,
                peer_pub_id: payee_pub_id.to_string(),
                role: nie_core::messages::PaymentRole::Payer,
                state: nie_core::messages::PaymentState::Sent,
                created_at: 1_000_000,
                updated_at: 1_000_000,
                tx_hash: None,
                address: None,
            };
            let mut sessions = HashMap::from([(session_id, session)]);
            let (tx, _rx) = tokio::sync::mpsc::channel(4);
            let mut mls = nie_core::mls::MlsClient::new("test-txhash-val").unwrap();
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let store = WalletStore::new(tmp.path()).await.unwrap();
            dispatch_payment(
                session_id,
                nie_core::messages::PaymentAction::Confirmed {
                    tx_hash: tx_hash.to_string(),
                },
                payee_pub_id,
                &mut sessions,
                &store,
                None,
                &HashMap::new(),
                &HashMap::new(),
                &tx,
                false,
                &mut mls,
                None,
                None,
            )
            .await
        }

        // Valid: exactly 64 lowercase hex → accepted (returns alive=true).
        assert!(
            try_confirm(session_id, &payee_pub_id, &"a".repeat(64)).await,
            "valid 64-char hex must be accepted"
        );
        // Too short.
        assert!(
            !try_confirm(session_id, &payee_pub_id, &"a".repeat(63)).await,
            "63-char hash must be rejected"
        );
        // Uppercase hex chars.
        assert!(
            !try_confirm(session_id, &payee_pub_id, &"A".repeat(64)).await,
            "uppercase hex must be rejected"
        );
        // Non-hex stub value.
        assert!(
            !try_confirm(session_id, &payee_pub_id, "txhash-not-hex").await,
            "non-hex stub must be rejected"
        );
    }
}

// ---- /dm slash command parse tests ----
#[cfg(test)]
mod dm_tests {
    use nie_core::messages::ClearMessage;

    #[test]
    fn test_dm_parse_handle_and_text_with_spaces() {
        let rest = "alice hello world from bob";
        let mut parts = rest.splitn(2, ' ');
        let handle = parts.next().unwrap_or("").trim();
        let text = parts.next().unwrap_or("").trim();
        assert_eq!(handle, "alice");
        assert_eq!(text, "hello world from bob");
    }

    #[test]
    fn test_dm_payload_roundtrip() {
        let text = "hello world".to_string();
        // serde_json::to_vec on derived Serialize with only String fields cannot fail
        let payload = serde_json::to_vec(&ClearMessage::Chat { text: text.clone() }).unwrap();
        // Oracle: independently deserialize; result must match the input string
        let decoded: ClearMessage = serde_json::from_slice(&payload).unwrap();
        match decoded {
            ClearMessage::Chat { text: decoded_text } => assert_eq!(decoded_text, text),
            _ => panic!("expected ClearMessage::Chat"),
        }
    }

    /// Oracle: independently constructed ClearMessage::Chat payload must dispatch
    /// to the Chat arm — verifying the WhisperDeliver DM path identifies JSON correctly.
    #[test]
    fn test_whisper_deliver_payload_is_clear_message() {
        let expected_text = "hello dm world";
        let payload = serde_json::to_vec(&ClearMessage::Chat {
            text: expected_text.to_string(),
        })
        .unwrap();
        match serde_json::from_slice::<ClearMessage>(&payload).unwrap() {
            ClearMessage::Chat { text } => assert_eq!(text, expected_text),
            _ => panic!("expected Chat variant"),
        }
    }

    /// MLS-like binary data must fail JSON parse, signalling the MLS Welcome path.
    #[test]
    fn test_whisper_deliver_binary_payload_not_json() {
        let binary_payload = vec![0x00, 0x01, 0x02, 0x03, 0xff];
        assert!(
            serde_json::from_slice::<ClearMessage>(&binary_payload).is_err(),
            "binary payload must not parse as ClearMessage"
        );
    }
}
