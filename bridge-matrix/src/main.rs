//! nie-bridge-matrix — bidirectional Matrix/nie bridge.
//!
//! Connects to a nie relay as a bot and bridges chat messages to/from a
//! configured Matrix room via the Application Service API.
//!
//! # Setup
//!
//! 1. Generate an identity: `nie init --data-dir /var/lib/nie-bridge`
//! 2. Create `bridge.toml` (see `BridgeConfig` docs for all fields).
//! 3. Register the AS with your homeserver (see `registration.yaml` example).
//! 4. Run: `nie-bridge-matrix --config bridge.toml`
//!
//! # Live testing
//!
//! Requires a running nie relay and Matrix homeserver. See DESIGN.md §bridge.

use anyhow::Result;
use clap::Parser;

mod bridge;
mod config;
mod matrix;

#[derive(Parser)]
#[command(name = "nie-bridge-matrix", about = "Matrix/nie chat bridge")]
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
                .add_directive("nie_bridge_matrix=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let config = config::BridgeConfig::from_toml(std::path::Path::new(&cli.config))?;
    bridge::run(&config).await
}
