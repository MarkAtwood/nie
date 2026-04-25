mod payment_watcher;

use std::net::SocketAddr;

use axum::{routing::get, Router};
use tracing::info;
use tracing_subscriber::EnvFilter;

use nie_relay::state::{AppState, MerchantWallet};
use nie_wallet::address::{SaplingDiversifiableFvk, ZcashNetwork};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:nie-relay.db?mode=rwc".to_string());

    let keepalive_secs: u64 = match std::env::var("KEEPALIVE_SECS") {
        Err(_) => 30,
        Ok(v) => match v.parse() {
            Ok(n) => n,
            // Warn rather than silently using the default — a misconfigured value
            // (e.g. "five") is an operator error that should surface at startup.
            Err(_) => {
                tracing::warn!("KEEPALIVE_SECS={v:?} is not a valid integer; using default 30");
                30
            }
        },
    };

    let require_subscription: bool = match std::env::var("REQUIRE_SUBSCRIPTION") {
        Err(_) => false,
        Ok(v) if v.eq_ignore_ascii_case("true") || v == "1" => true,
        Ok(v) if v.eq_ignore_ascii_case("false") || v == "0" => false,
        // Warn explicitly: "yes" or "on" silently left subscription gating off,
        // which is a business-logic error that could allow unpaid access.
        Ok(v) => {
            tracing::warn!(
                "REQUIRE_SUBSCRIPTION={v:?} is not recognized (expected true/false/1/0); \
                 using default false — subscription gating is OFF"
            );
            false
        }
    };

    let subscription_price_zatoshi: u64 = match std::env::var("SUBSCRIPTION_PRICE_ZATOSHI") {
        Err(_) => 1_000_000,
        Ok(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    "SUBSCRIPTION_PRICE_ZATOSHI={v:?} is not a valid integer; using default 1000000"
                );
                1_000_000
            }
        },
    };

    let subscription_days: u64 = match std::env::var("SUBSCRIPTION_DAYS") {
        Err(_) => 30,
        Ok(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!("SUBSCRIPTION_DAYS={v:?} is not a valid integer; using default 30");
                30
            }
        },
    };

    let rate_limit_per_min: u32 = match std::env::var("RATE_LIMIT_MSG_PER_MIN") {
        Err(_) => 120,
        Ok(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    "RATE_LIMIT_MSG_PER_MIN={v:?} is not a valid integer; using default 120"
                );
                120
            }
        },
    };
    tracing::info!(rate_limit_per_min, "rate limit configured");

    let state = AppState::new(
        &db_url,
        keepalive_secs,
        require_subscription,
        subscription_price_zatoshi,
        subscription_days,
        rate_limit_per_min,
    )
    .await?;

    let pow_difficulty: u8 = std::env::var("POW_DIFFICULTY")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0); // 0 = disabled; safe default
    anyhow::ensure!(
        pow_difficulty == 0 || pow_difficulty <= nie_core::pow::MAX_DIFFICULTY,
        "POW_DIFFICULTY={pow_difficulty} exceeds MAX_DIFFICULTY ({}); \
         clients would permanently fail PoW verification — refusing to start",
        nie_core::pow::MAX_DIFFICULTY,
    );
    if pow_difficulty > 0 && pow_difficulty < 20 {
        tracing::warn!(
            pow_difficulty,
            "POW_DIFFICULTY below minimum 20; clamping to 20"
        );
        state.set_pow_difficulty(20);
    } else {
        state.set_pow_difficulty(pow_difficulty);
    }
    tracing::info!(
        pow_difficulty = state.pow_difficulty(),
        "PoW enrollment gate configured"
    );

    let directory_expiry_days: u64 = match std::env::var("DIRECTORY_EXPIRY_DAYS") {
        Err(_) => 90,
        Ok(v) if v == "0" => 0,
        Ok(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    "DIRECTORY_EXPIRY_DAYS={v:?} is not a valid integer; using default 90"
                );
                90
            }
        },
    };
    if directory_expiry_days == 0 {
        info!("directory expiry disabled (DIRECTORY_EXPIRY_DAYS=0)");
    } else {
        info!(directory_expiry_days, "directory expiry configured");
        // Run once at startup, then every 24 hours.
        let prune_state = state.clone();
        tokio::spawn(async move {
            loop {
                match prune_state
                    .inner
                    .store
                    .prune_inactive_users(directory_expiry_days)
                    .await
                {
                    Ok(n) if n > 0 => {
                        info!(pruned = n, "pruned inactive directory entries");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("directory prune failed: {e}");
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(86_400)).await;
            }
        });
    }

    if let Some(merchant) = load_merchant_wallet() {
        tracing::info!("merchant wallet loaded, network={:?}", merchant.network);
        state.set_merchant(merchant);

        // Spawn payment watcher if LIGHTWALLETD_URL is configured.
        // The watcher polls for confirmed Zcash payments and activates subscriptions.
        match std::env::var("LIGHTWALLETD_URL") {
            Ok(url) => {
                info!("payment_watcher: starting, lightwalletd_url={url}");
                payment_watcher::spawn_payment_watcher(state.clone(), url);
            }
            Err(_) => {
                tracing::warn!(
                    "LIGHTWALLETD_URL not set — payment watcher disabled; subscriptions must be activated manually"
                );
            }
        }
    } else {
        tracing::warn!("MERCHANT_DFVK not set — relay will operate without payment gating");
    }

    let app = Router::new()
        .route("/ws", get(nie_relay::ws::ws_handler))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3210".to_string())
        .parse()?;

    info!("nie-relay listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Load the merchant DFVK from environment variables.
///
/// Reads `MERCHANT_DFVK` (256 hex chars = 128 bytes) and `MERCHANT_NETWORK`
/// ("mainnet" or "testnet", defaulting to "testnet").  Returns `None` if
/// `MERCHANT_DFVK` is absent — the relay starts without payment gating.
///
/// The DFVK bytes are never logged; only the network is logged on success.
fn load_merchant_wallet() -> Option<MerchantWallet> {
    let hex = match std::env::var("MERCHANT_DFVK") {
        Err(_) => return None,
        Ok(v) => v,
    };

    let network = match std::env::var("MERCHANT_NETWORK") {
        Err(_) => {
            tracing::warn!(
                "MERCHANT_NETWORK not set, defaulting to testnet \
                 — set MERCHANT_NETWORK=mainnet for production"
            );
            ZcashNetwork::Testnet
        }
        Ok(v) => match v.to_lowercase().as_str() {
            "mainnet" => ZcashNetwork::Mainnet,
            "testnet" => ZcashNetwork::Testnet,
            _ => {
                tracing::error!(
                    "MERCHANT_NETWORK={v:?} is not recognized (expected mainnet or testnet); \
                     refusing to start with an unknown network"
                );
                return None;
            }
        },
    };

    let bytes: [u8; 128] = match decode_hex_128(&hex) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("MERCHANT_DFVK invalid: {e}");
            return None;
        }
    };

    let dfvk = match SaplingDiversifiableFvk::from_bytes(&bytes) {
        Some(k) => k,
        None => {
            tracing::error!("MERCHANT_DFVK bytes do not form a valid Sapling DFVK");
            return None;
        }
    };

    Some(MerchantWallet { dfvk, network })
}

/// Decode a 256-character lowercase hex string into exactly 128 bytes.
fn decode_hex_128(s: &str) -> anyhow::Result<[u8; 128]> {
    if s.len() != 256 {
        anyhow::bail!("expected 256 hex chars (128 bytes), got {} chars", s.len());
    }
    let mut out = [0u8; 128];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> anyhow::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("invalid hex character: {}", b as char),
    }
}
