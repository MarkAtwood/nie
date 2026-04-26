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
mod jmap;
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

    // CORS: allow localhost origins on the configured port.
    // Derive the port from LISTEN_ADDR so CORS stays consistent when operators
    // change the port via the env var.
    let port = socket_addr.port();
    let cors = CorsLayer::new()
        .allow_origin([
            format!("http://localhost:{port}").parse::<HeaderValue>()?,
            format!("http://127.0.0.1:{port}").parse::<HeaderValue>()?,
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    // Load identity from keyfile to get pub_id.  Default location mirrors nie-cli.
    let keyfile_path = std::env::var("KEYFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("identity.key"));

    let my_pub_id = if keyfile_path.exists() {
        match std::fs::read(&keyfile_path)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        {
            Some(arr) => Identity::from_secret_bytes(&arr)?.pub_id().0,
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

    // Build router.  /api/* and JMAP routes require Bearer token auth;
    // /health and /ws/events do their own auth.
    let api_router = Router::new()
        .route("/api/whoami", get(api::handle_whoami))
        .route("/api/users", get(api::handle_users))
        .route("/api/send", post(api::handle_send))
        .route("/api/wallet/balance", get(api::handle_wallet_balance))
        .route("/api/wallet/pay", post(api::handle_wallet_pay))
        // JMAP Core (RFC 8620)
        .route("/.well-known/jmap", get(jmap::handle_jmap_session))
        .route("/jmap", post(jmap::handle_jmap_request))
        .route("/jmap/upload/{account_id}", post(jmap::handle_jmap_upload))
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(jmap::handle_jmap_download),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            daemon_state.clone(),
            token::require_token,
        ));

    // Routes that accept ?token= for browser clients (WebSocket and EventSource APIs
    // cannot set Authorization headers). The token is stripped from the request URI
    // by a middleware layer so it cannot appear in access logs if a TraceLayer is
    // added in the future.
    let browser_auth_routes = Router::new()
        .route("/ws/events", get(ws_events::handle_ws_events))
        .route("/jmap/eventsource/", get(jmap::handle_jmap_eventsource))
        .route_layer(axum::middleware::from_fn(redact_token_query_param));

    let app = Router::new()
        .route("/", get(web::handle_index))
        .route("/index.html", get(web::handle_index))
        .route("/health", get(|| async { "ok" }))
        .merge(browser_auth_routes)
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

    // Background task: hard-delete expired messages every 60 seconds.
    let expiry_state = daemon_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Some(store) = expiry_state.store() {
                match store.hard_delete_expired_messages().await {
                    Ok(n) if n > 0 => tracing::info!("expiry reaper: deleted {n} expired messages"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("expiry reaper: {e}"),
                }
            }
        }
    });

    // Connect to relay if RELAY_URL is set and a keyfile exists.
    if let Ok(relay_url) = std::env::var("RELAY_URL") {
        let insecure = std::env::var("RELAY_INSECURE").is_ok();
        let proxy = std::env::var("RELAY_PROXY").ok();
        let keyfile_str = keyfile_path.to_str().ok_or_else(|| {
            anyhow::anyhow!("keyfile path contains non-UTF-8 bytes: {keyfile_path:?}")
        })?;
        relay::start_relay_connector(keyfile_str, &relay_url, insecure, proxy, daemon_state)
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

/// Middleware that logs a sanitized request URI (with `?token=` redacted) at
/// trace level, then passes the original request through unchanged.
///
/// Browser WebSocket and EventSource APIs cannot set Authorization headers, so
/// they must send the bearer token as a query parameter. Mutating the URI here
/// would break the `Query` extractor in downstream handlers — each handler
/// reads `?token=` itself and performs its own constant-time comparison.
///
/// Redaction is case-insensitive (`token=`, `TOKEN=`, `Token=`, etc.) and also
/// matches the URL-encoded form `%74oken=` (lowercase 't' percent-encoded as
/// `%74`).  A parameter is a token parameter if its name, when lowercased and
/// with `%74` replaced by `t`, is `"token"`.
async fn redact_token_query_param(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if tracing::enabled!(tracing::Level::TRACE) {
        let uri = req.uri();
        if let Some(query) = uri.query() {
            // Detect any token= variant (case-insensitive, URL-encoded) before
            // allocating the redacted string.
            let lower = query.to_ascii_lowercase();
            let normalized = lower.replace("%74oken", "token");
            if normalized.contains("token=") {
                let redacted: String = query
                    .split('&')
                    .map(|param| {
                        // Extract the param name (everything before '=' or the
                        // whole param if there is no '=').
                        let name = param.split('=').next().unwrap_or(param);
                        let name_lower = name.to_ascii_lowercase();
                        let name_norm = name_lower.replace("%74oken", "token");
                        if name_norm == "token" {
                            "token=REDACTED"
                        } else {
                            param
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                tracing::trace!(
                    path = uri.path(),
                    query = %redacted,
                    "browser-auth request (token redacted)"
                );
            }
        }
    }
    next.run(req).await
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
