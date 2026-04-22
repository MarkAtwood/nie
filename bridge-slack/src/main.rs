//! nie-bridge-slack — bidirectional Slack/nie bridge.
//!
//! Connects to a nie relay as a bot and bridges chat messages to/from a
//! configured Slack channel via the Slack Events API.
//!
//! # Setup
//!
//! 1. Generate an identity: `nie init --data-dir /var/lib/nie-bridge-slack`
//! 2. Create `bridge.toml` (see `BridgeConfig` docs for all fields).
//! 3. Configure the Slack app: enable Events API, subscribe to `message.channels`.
//! 4. Run: `nie-bridge-slack --config bridge.toml`
//!
//! # Live testing
//!
//! Requires a running nie relay and a Slack workspace with the bot installed.
//! Use ngrok to expose the local HTTP server for Slack event delivery.

use anyhow::Result;
use clap::Parser;

mod bridge;
mod config;
mod slack;

#[derive(Parser)]
#[command(name = "nie-bridge-slack", about = "Slack/nie chat bridge")]
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
                .add_directive("nie_bridge_slack=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let config = config::BridgeConfig::from_toml(std::path::Path::new(&cli.config))?;
    bridge::run(&config).await
}
