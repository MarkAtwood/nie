use anyhow::{Context, Result};
use axum::{
    http::{HeaderValue, Method},
    routing::{get, post},
    Router,
};
use nie_core::identity::Identity;
use std::path::PathBuf;
use tower_http::cors::CorsLayer;

mod api;
mod pid;
mod relay;
mod state;
mod store;
mod token;
mod types;
mod web;
mod ws_events;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Resolve data directory
    let data_dir = data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    // Load or create token
    let tok = token::load_or_create_token(&data_dir)?;

    // PID file
    let pid_path = data_dir.join("daemon.pid");
    pid::acquire_pid_file(&pid_path)?;

    // Parse and validate listen address
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:7734".to_string());
    let socket_addr: std::net::SocketAddr = listen_addr.parse()?;
    anyhow::ensure!(
        socket_addr.ip().is_loopback(),
        "LISTEN_ADDR must be a loopback address, got: {}",
        socket_addr.ip()
    );

    // CORS: allow localhost origins only
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:7734".parse::<HeaderValue>()?,
            "http://127.0.0.1:7734".parse::<HeaderValue>()?,
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    // Load identity from keyfile to get pub_id.  Default location mirrors nie-cli.
    let keyfile_path = std::env::var("KEYFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("identity.key"));

    let my_pub_id = if keyfile_path.exists() {
        match std::fs::read(&keyfile_path)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        {
            Some(arr) => Identity::from_secret_bytes(&arr).pub_id().0,
            None => {
                anyhow::bail!(
                    "keyfile {} must be exactly 64 bytes",
                    keyfile_path.display()
                );
            }
        }
    } else {
        tracing::warn!(
            "no keyfile at {}; run 'nie init' first or set KEYFILE",
            keyfile_path.display()
        );
        // Daemon starts without an identity; /api/whoami will reflect this.
        "no_identity".to_string()
    };

    // Zcash network selection: NETWORK env var, default "mainnet".
    let network = std::env::var("NETWORK").unwrap_or_else(|_| "mainnet".to_string());

    // Try to open wallet DB if present (wallet.db in data dir).
    let wallet_store = {
        let db_path = data_dir.join("wallet.db");
        if db_path.exists() {
            match nie_wallet::db::WalletStore::new(&db_path).await {
                Ok(ws) => Some(ws),
                Err(e) => {
                    tracing::warn!("failed to open wallet.db: {e}");
                    None
                }
            }
        } else {
            None
        }
    };

    // Open JMAP Chat store (creates jmap.db in data dir if not present)
    let db_url = std::env::var("JMAP_DATABASE_URL")
        .unwrap_or_else(|_| format!("sqlite:{}?mode=rwc", data_dir.join("jmap.db").display()));
    let jmap_store = store::Store::new(&db_url)
        .await
        .context("open JMAP store")?;

    // Create app state
    let daemon_state = state::DaemonState::new(
        my_pub_id,
        tok.clone(),
        None,
        network,
        wallet_store,
        Some(jmap_store),
    );

    // Bootstrap default Space and channel in the JMAP store.
    // daemon_state.store() is Some because we always pass Some(jmap_store) above.
    let bootstrap_store = daemon_state.store().expect("jmap store must be present");
    let space_name = std::env::var("NIE_SPACE_NAME").unwrap_or_else(|_| "nie".to_string());
    let channel_name = std::env::var("NIE_CHANNEL_NAME").unwrap_or_else(|_| "general".to_string());

    let space_id = match bootstrap_store
        .find_space_by_name(&space_name)
        .await
        .context("find default space")?
    {
        Some(id) => id,
        None => {
            let id = store::Store::new_id();
            bootstrap_store
                .create_space(&id, &space_name)
                .await
                .context("create default space")?;
            tracing::info!(space_id = %id, name = %space_name, "bootstrapped default space");
            id
        }
    };

    let channel_id = match bootstrap_store
        .find_channel_in_space(&space_id)
        .await
        .context("find default channel")?
    {
        Some(id) => id,
        None => {
            let id = store::Store::new_id();
            bootstrap_store
                .create_channel(&id, &channel_name, &space_id)
                .await
                .context("create default channel")?;
            tracing::info!(channel_id = %id, name = %channel_name, "bootstrapped default channel");
            id
        }
    };

    daemon_state.set_default_space_id(space_id);
    daemon_state.set_default_channel_id(channel_id);

    // Build router.  /api/* routes require Bearer token auth; other routes do
    // not (ws/events does its own auth check inside the handler).
    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/api/users", get(api::handle_users))
        .route("/api/send", post(api::handle_send))
        .route("/api/wallet/balance", get(api::handle_wallet_balance))
        .route("/api/wallet/pay", post(api::handle_wallet_pay))
        .route_layer(axum::middleware::from_fn_with_state(
            daemon_state.clone(),
            token::require_token,
        ));

    let app = Router::new()
        .route("/", get(web::handle_index))
        .route("/index.html", get(web::handle_index))
        .route("/health", get(|| async { "ok" }))
        .route("/ws/events", get(ws_events::handle_ws_events))
        .merge(api_router)
        .layer(cors)
        .with_state(daemon_state.clone());

    // Bind listener
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;
    tracing::info!("nie-daemon listening on {}", listener.local_addr()?);
    tracing::info!(
        "token stored at {}",
        data_dir.join("daemon.token").display()
    );

    // Connect to relay if RELAY_URL is set and a keyfile exists.
    if let Ok(relay_url) = std::env::var("RELAY_URL") {
        let insecure = std::env::var("RELAY_INSECURE").is_ok();
        let proxy = std::env::var("RELAY_PROXY").ok();
        relay::start_relay_connector(
            keyfile_path.to_str().unwrap_or(""),
            &relay_url,
            insecure,
            proxy,
            daemon_state,
        )
        .await?;
        tracing::info!("relay connector started for {}", relay_url);
    } else {
        tracing::info!("RELAY_URL not set; daemon running without relay connection");
    }

    // Clean up PID on ctrl-c
    let pid_path_clone = pid_path.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        pid::release_pid_file(&pid_path_clone);
        std::process::exit(0);
    });

    axum::serve(listener, app).await?;
    pid::release_pid_file(&pid_path);
    Ok(())
}

fn data_dir() -> Result<PathBuf> {
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local/share"))
        })
        .ok_or_else(|| anyhow::anyhow!("cannot determine data directory (HOME not set)"))?;
    Ok(base.join("nie"))
}
