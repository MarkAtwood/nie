use nie_tui::{app, event};

use anyhow::Result;
use clap::Parser;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use nie_cli_lib::config;
use nie_core::{keyfile::load_identity, mls::MlsClient, transport};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, stdout},
    path::PathBuf,
};
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "nie-tui", about = "nie encrypted relay TUI client")]
struct Cli {
    /// WebSocket relay URL (ws:// or wss://)
    #[arg(long)]
    relay: Option<String>,

    /// Path to identity keyfile
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// Override data directory (default: $XDG_DATA_HOME/nie)
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Zcash network: "mainnet" or "testnet"
    #[arg(long, default_value = "testnet", value_parser = ["mainnet", "testnet"])]
    network: String,

    /// lightwalletd gRPC endpoint URL
    #[arg(long)]
    lightwalletd: Option<String>,

    /// SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:9050)
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Skip TLS certificate verification (dev only)
    #[arg(long, hide = true)]
    insecure: bool,

    /// Skip passphrase protection (CI/testing only)
    #[arg(long, hide = true)]
    no_passphrase: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging to stderr so it doesn't corrupt the TUI output on stdout.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();

    // Resolve data dir (create if absent).
    let data_dir = match cli.data_dir {
        Some(d) => {
            std::fs::create_dir_all(&d)?;
            d
        }
        None => config::data_dir()?,
    };

    // Load persistent config; missing file is not an error.
    let file_cfg = config::AppConfig::load(&config::config_dir()?)?;

    // Priority: --relay flag > config.toml > compiled default.
    let relay = cli
        .relay
        .or(file_cfg.relay)
        .unwrap_or_else(|| "ws://127.0.0.1:3210/ws".to_string());

    if !relay.starts_with("ws://") && !relay.starts_with("wss://") {
        let scheme = relay.split("://").next().unwrap_or(&relay);
        anyhow::bail!(
            "relay URL must use ws:// or wss:// scheme (got: \"{}://...\"). \
             Use --relay wss://your-relay/ws or set relay in config.toml.",
            scheme
        );
    }

    // Priority: --proxy flag > config.toml > None.
    let proxy: Option<String> = cli.proxy.or(file_cfg.proxy);

    if let Some(ref p) = proxy {
        if !p.starts_with("socks5://") && !p.starts_with("socks5h://") {
            anyhow::bail!("proxy URL must start with socks5:// or socks5h://");
        }
        if relay.contains(".onion") && p.starts_with("socks5://") && !p.starts_with("socks5h://") {
            warn!(
                "relay is .onion but proxy scheme is socks5:// — DNS will be resolved locally \
                 before the Tor tunnel; use socks5h:// to prevent DNS leak"
            );
        }
    } else if relay.contains(".onion") {
        warn!(
            ".onion relay address without a SOCKS5 proxy — connection will likely fail without \
             Tor; use --proxy socks5h://127.0.0.1:9050"
        );
    }

    // Resolve keyfile path.
    let keyfile = cli
        .keyfile
        .unwrap_or_else(|| data_dir.join("identity.key"))
        .to_string_lossy()
        .into_owned();

    // Load identity (prompts for passphrase unless --no-passphrase).
    let identity = load_identity(&keyfile, cli.no_passphrase)?;

    // Extract public info before moving identity into the transport layer.
    let my_pub_id = identity.pub_id().0.clone();
    let hpke_secret = identity.hpke_secret_bytes();
    let hpke_pub = identity.hpke_pub_key_bytes();

    // Create MLS client.
    let mls_client = MlsClient::new(&my_pub_id)?;

    // Build app state.
    let mut state = app::AppState::new(my_pub_id, *hpke_secret, hpke_pub, mls_client);

    // Try to open wallet DB — optional; payment commands degrade gracefully without it.
    let wallet_path = data_dir.join("wallet.db");
    if wallet_path.exists() {
        match nie_wallet::db::WalletStore::new(&wallet_path).await {
            Ok(ws) => {
                if let Err(e) = ws.ensure_account(0).await {
                    warn!("wallet ensure_account failed: {e}");
                }
                state.wallet = Some(std::sync::Arc::new(ws));
                tracing::info!("wallet loaded");
            }
            Err(e) => {
                warn!("wallet open failed: {e}");
            }
        }
    }

    // Connect to relay with automatic reconnection.
    // connect_with_retry spawns a background task and returns immediately.
    let conn = transport::connect_with_retry(relay, identity, cli.insecure, proxy);

    // Install panic hook BEFORE terminal initialisation so the terminal is
    // restored even if we panic during setup.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Restore terminal synchronously (no async context here).
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        eprintln!("nie-tui panic: {info}");
        default_hook(info);
    }));

    // Initialise terminal.
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    // Run the event loop; always restore terminal on exit, even on error.
    let result = event::run(&mut terminal, &mut state, conn).await;

    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);

    result
}
