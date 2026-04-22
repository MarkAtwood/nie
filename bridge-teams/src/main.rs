//! nie-bridge-teams — bidirectional Microsoft Teams/nie bridge.
//!
//! Connects to a nie relay as a bot and bridges chat messages to/from a
//! configured Microsoft Teams channel.
//!
//! # Setup
//!
//! 1. Generate an identity: `nie init --data-dir /var/lib/nie-bridge-teams`
//! 2. Create `bridge.toml` (see `BridgeConfig` docs for all fields).
//! 3. In Teams admin: add an "Incoming Webhook" connector to the channel and
//!    copy the URL to `teams_incoming_webhook_url`.
//! 4. In Teams admin: add an "Outgoing Webhook" pointing to
//!    `https://<your-host>:<listen_port>/teams/webhook` and copy the security
//!    token to `teams_security_token`.
//! 5. Run: `nie-bridge-teams --config bridge.toml`
//!
//! # Note on outgoing webhook scope
//!
//! Teams outgoing webhooks are triggered when a message @mentions the webhook
//! name.  Channel members must @mention the bridge bot for their messages to
//! cross to nie.  For full bidirectional bridging without @mentions, use the
//! Microsoft Bot Framework instead.

use anyhow::Result;
use clap::Parser;

mod bridge;
mod config;
mod teams;

#[derive(Parser)]
#[command(name = "nie-bridge-teams", about = "Microsoft Teams/nie chat bridge")]
struct Cli {
    /// Path to bridge.toml configuration file.
    #[arg(long, default_value = "bridge.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nie_bridge_teams=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let config = config::BridgeConfig::from_toml(std::path::Path::new(&cli.config))?;
    bridge::run(&config).await
}
