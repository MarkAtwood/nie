//! nie-bridge-jmap — bidirectional JMAP/nie bridge.
//!
//! Connects to a nie relay as a bot and bridges chat messages to/from a
//! configured JMAP mailbox.
//!
//! # Setup
//!
//! 1. Generate an identity: `nie init --data-dir /var/lib/nie-bridge-jmap`
//! 2. Create `bridge.toml` (see `BridgeConfig` docs for all fields).
//! 3. Obtain a JMAP bearer token and mailbox ID from your JMAP provider.
//! 4. Run: `nie-bridge-jmap --config bridge.toml`
//!
//! # Message flow
//!
//! New emails appearing in the configured JMAP mailbox are forwarded to the
//! nie room as Chat messages.  Chat messages from the nie room are deposited
//! into the same JMAP mailbox as new emails.
//!
//! The bridge polls the JMAP server at `poll_interval_secs` (default 30s).
//! JMAP push/SSE is not currently implemented.

use anyhow::Result;
use clap::Parser;

mod bridge;
mod config;
mod jmap;

#[derive(Parser)]
#[command(name = "nie-bridge-jmap", about = "JMAP/nie chat bridge")]
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
                .add_directive("nie_bridge_jmap=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let config = config::BridgeConfig::from_toml(std::path::Path::new(&cli.config))?;
    bridge::run(&config).await
}
