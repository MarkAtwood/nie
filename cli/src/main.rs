mod commands;
mod config;
mod history;
mod profile;

use clap::{Parser, Subcommand};
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "nie", about = "encrypted relay client (囁)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Relay WebSocket URL. Overrides config.toml if set.
    #[arg(long, global = true)]
    relay: Option<String>,

    /// Path to identity keyfile (default: <data-dir>/identity.key).
    #[arg(long, global = true)]
    keyfile: Option<String>,

    /// Override the nie data directory.
    #[arg(long, global = true)]
    data_dir: Option<String>,

    /// Skip TLS certificate verification. Dev only — never use in production.
    #[arg(long, global = true, hide = true)]
    insecure: bool,

    /// Skip passphrase protection. Testing and CI only — identity key will NOT be encrypted.
    #[arg(long, global = true, hide = true)]
    no_passphrase: bool,

    /// Zcash network: "mainnet" or "testnet".
    #[arg(long, global = true, default_value = "testnet", value_parser = ["mainnet", "testnet"])]
    network: String,

    /// lightwalletd gRPC endpoint URL. Overrides config.toml and network defaults.
    #[arg(long, global = true)]
    lightwalletd: Option<String>,

    /// SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:9050 for Tor; socks5h:// recommended for .onion addresses).
    #[arg(long, global = true, value_name = "URL")]
    proxy: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new identity keypair.
    Init,
    /// Print your public identity hash.
    Whoami,
    /// Join the chat room.
    Chat,
    /// Show local message history.
    Log {
        /// Number of recent messages to show (default: 100).
        #[arg(short = 'n', default_value = "100")]
        limit: i64,
    },
    /// Zcash wallet management.
    Wallet {
        #[command(subcommand)]
        cmd: WalletCmd,
    },
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Generate a new Zcash wallet (BIP-39 mnemonic + ZIP-32 Sapling master key).
    Init {
        /// Overwrite existing wallet.key (THIS WILL DESTROY YOUR EXISTING WALLET).
        #[arg(long)]
        force: bool,
    },
    /// Restore wallet from a BIP-39 mnemonic phrase.
    Restore {
        /// Overwrite existing wallet.key.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();

    let data_dir = match cli.data_dir {
        Some(p) => {
            let path = std::path::PathBuf::from(&p);
            std::fs::create_dir_all(&path)?;
            path
        }
        None => config::data_dir()?,
    };

    // Priority: --relay flag > config.toml > compiled default.
    let file_config = config::AppConfig::load(&config::config_dir()?)?;
    let relay = cli
        .relay
        .or(file_config.relay)
        .unwrap_or_else(|| "ws://127.0.0.1:3210/ws".to_string());

    // Priority: --lightwalletd flag > config.toml > network default (resolved in commands.rs).
    let lightwalletd: Option<String> = cli.lightwalletd.or(file_config.lightwalletd);

    // Priority: --proxy flag > config.toml > None.
    let proxy: Option<String> = cli.proxy.or(file_config.proxy);

    for w in validate_proxy_config(proxy.as_deref(), &relay)? {
        warn!("{w}");
    }

    let keyfile = cli
        .keyfile
        .unwrap_or_else(|| data_dir.join("identity.key").to_string_lossy().into_owned());

    match cli.cmd {
        Cmd::Init => commands::init(&keyfile, cli.no_passphrase).await?,
        Cmd::Whoami => commands::whoami(&keyfile, cli.no_passphrase).await?,
        Cmd::Chat => {
            let scheme_ok = relay.starts_with("ws://") || relay.starts_with("wss://");
            if !scheme_ok {
                let got = relay.split("://").next().unwrap_or(&relay);
                anyhow::bail!(
                    "relay URL must use ws:// or wss:// scheme (got: \"{}://...\"). \
                     Use --relay wss://your-relay/ws or set relay in config.toml.",
                    got
                );
            }
            if let Some(ref lwd) = lightwalletd {
                let scheme_ok = lwd.starts_with("https://") || lwd.starts_with("grpc+tls://");
                if !scheme_ok {
                    let got = lwd.split("://").next().unwrap_or(lwd);
                    anyhow::bail!(
                        "lightwalletd URL must use https:// or grpc+tls:// scheme \
                         (got: \"{}://...\"). Use --lightwalletd https://your-endpoint \
                         or set lightwalletd in config.toml.",
                        got
                    );
                }
            }
            commands::chat(
                &keyfile,
                &data_dir,
                &relay,
                cli.insecure,
                cli.no_passphrase,
                &cli.network,
                lightwalletd,
                proxy,
            )
            .await?
        }
        Cmd::Log { limit } => commands::log(&data_dir, limit).await?,
        Cmd::Wallet { cmd } => match cmd {
            WalletCmd::Init { force } => {
                commands::wallet_init(&data_dir, &cli.network, cli.no_passphrase, force).await?
            }
            WalletCmd::Restore { force } => {
                commands::wallet_restore(&data_dir, &cli.network, cli.no_passphrase, force).await?
            }
        },
    }

    Ok(())
}

/// Validate the proxy URL scheme and warn about .onion misconfigurations.
///
/// Returns `Ok(warnings)` where each element is a warning message to be logged.
/// Returns `Err` if the proxy URL scheme is invalid.
fn validate_proxy_config(proxy: Option<&str>, relay: &str) -> anyhow::Result<Vec<&'static str>> {
    if let Some(p) = proxy {
        if !p.starts_with("socks5://") && !p.starts_with("socks5h://") {
            anyhow::bail!("proxy URL must start with socks5:// or socks5h://");
        }
    }

    let mut warnings: Vec<&'static str> = Vec::new();

    if relay.contains(".onion") {
        match proxy {
            None => {
                warnings.push(".onion relay address without a SOCKS5 proxy — connection will likely fail without Tor; use --proxy socks5h://127.0.0.1:9050");
            }
            Some(p) if p.starts_with("socks5://") && !p.starts_with("socks5h://") => {
                warnings.push("relay is .onion but proxy scheme is socks5:// — DNS will be resolved locally before the Tor tunnel; use socks5h:// to prevent DNS leak");
            }
            _ => {}
        }
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_proxy_scheme_returns_err() {
        let result =
            validate_proxy_config(Some("http://127.0.0.1:3128"), "ws://relay.example.com/ws");
        assert!(result.is_err(), "http:// proxy must be rejected");
        let msg = format!("{}", result.err().unwrap());
        assert!(
            msg.contains("socks5"),
            "error must mention socks5, got: {msg}"
        );
    }

    #[test]
    fn onion_no_proxy_warns() {
        let warnings = validate_proxy_config(None, "ws://abc123.onion/ws")
            .expect("no proxy with .onion is Ok, not Err");
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("SOCKS5 proxy"),
            "warning must mention SOCKS5 proxy, got: {}",
            warnings[0]
        );
    }

    #[test]
    fn onion_socks5_warns_dns_leak() {
        let warnings =
            validate_proxy_config(Some("socks5://127.0.0.1:9050"), "ws://abc123.onion/ws")
                .expect("socks5:// with .onion is Ok, not Err");
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("DNS"),
            "warning must mention DNS leak, got: {}",
            warnings[0]
        );
    }

    #[test]
    fn onion_socks5h_no_warn() {
        let warnings =
            validate_proxy_config(Some("socks5h://127.0.0.1:9050"), "ws://abc123.onion/ws")
                .expect("socks5h:// with .onion is Ok");
        assert!(
            warnings.is_empty(),
            "socks5h:// with .onion must produce no warnings"
        );
    }

    #[test]
    fn no_onion_no_proxy_no_warn() {
        let warnings = validate_proxy_config(None, "wss://relay.example.com/ws")
            .expect("normal relay with no proxy is Ok");
        assert!(warnings.is_empty());
    }

    #[test]
    fn socks5_proxy_non_onion_relay_no_warn() {
        let warnings = validate_proxy_config(
            Some("socks5://127.0.0.1:9050"),
            "wss://relay.example.com/ws",
        )
        .expect("socks5:// with non-.onion relay is Ok");
        assert!(warnings.is_empty());
    }
}
