use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;

use crate::BotError;

/// Raw config deserialized from bot.toml (all fields optional).
#[derive(Debug, Deserialize, Default)]
pub struct BotConfig {
    pub relay: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub log_level: Option<String>,
    pub proxy: Option<String>,
    pub on_message_hook: Option<String>,
    pub auto_payment_address: Option<bool>,
}

impl BotConfig {
    /// Load from `config_dir/bot.toml`. Returns default if file is absent.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("bot.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("bot.toml parse error: {e}"))
    }
}

/// Resolved config: CLI flags > env vars > bot.toml > compiled defaults.
#[derive(Debug, Clone)]
pub struct ResolvedBotConfig {
    pub relay: String,
    pub keyfile: PathBuf,
    pub log_level: String,
    pub proxy: Option<String>,
    pub on_message_hook: Option<String>,
    pub auto_payment_address: bool,
    pub self_test: bool,
    pub insecure: bool,
    pub no_passphrase: bool,
}

/// Merge CLI args with file config using precedence: CLI > env > file > default.
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    cli_relay: Option<String>,
    cli_keyfile: Option<String>,
    cli_data_dir: Option<String>,
    cli_proxy: Option<String>,
    cli_on_message_hook: Option<String>,
    cli_auto_payment_address: bool,
    cli_self_test: bool,
    cli_insecure: bool,
    cli_no_passphrase: bool,
    cli_log_level: Option<String>,
    file: BotConfig,
) -> Result<ResolvedBotConfig> {
    // relay: CLI > env RELAY > file > default
    let relay = cli_relay
        .or_else(|| std::env::var("RELAY").ok().filter(|s| !s.is_empty()))
        .or(file.relay)
        .unwrap_or_else(|| "ws://127.0.0.1:3210/ws".to_string());

    // validate relay scheme
    if !relay.starts_with("ws://") && !relay.starts_with("wss://") {
        return Err(BotError::Config(format!(
            "relay URL must start with ws:// or wss://, got: {relay}"
        ))
        .into());
    }

    // keyfile: CLI > env KEYFILE > file > data_dir/identity.key
    let data_dir = cli_data_dir
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("XDG_DATA_HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|d| PathBuf::from(d).join("nie"))
        })
        .unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("nie")
        });

    let keyfile = cli_keyfile
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("KEYFILE")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or(file.keyfile)
        .unwrap_or_else(|| data_dir.join("identity.key"));

    // log_level: CLI > env LOG_LEVEL > file > "warn"
    let log_level = cli_log_level
        .or_else(|| std::env::var("LOG_LEVEL").ok().filter(|s| !s.is_empty()))
        .or(file.log_level)
        .unwrap_or_else(|| "warn".to_string());

    // proxy: CLI > env PROXY > file > None
    let proxy = cli_proxy
        .or_else(|| std::env::var("PROXY").ok().filter(|s| !s.is_empty()))
        .or(file.proxy);

    let on_message_hook = cli_on_message_hook.or(file.on_message_hook);
    let auto_payment_address =
        cli_auto_payment_address || file.auto_payment_address.unwrap_or(false);

    Ok(ResolvedBotConfig {
        relay,
        keyfile,
        log_level,
        proxy,
        on_message_hook,
        auto_payment_address,
        self_test: cli_self_test,
        insecure: cli_insecure,
        no_passphrase: cli_no_passphrase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that read or write the `RELAY` environment variable.
    // Without this, `test_env_relay_overrides_file` (which sets RELAY) can race
    // with `test_empty_toml_returns_defaults` (which expects RELAY to be unset).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: call resolve() with all-None / false args and a given BotConfig.
    fn resolve_defaults(file: BotConfig) -> Result<ResolvedBotConfig> {
        resolve(
            None, None, None, None, None, false, false, false, false, None, file,
        )
    }

    #[test]
    fn test_full_toml_parse() {
        let toml_str = r#"
relay = "wss://test.example.com/ws"
keyfile = "/tmp/test.key"
log_level = "debug"
proxy = "socks5h://127.0.0.1:9050"
on_message_hook = "/usr/bin/notify"
auto_payment_address = true
"#;
        let cfg: BotConfig = toml::from_str(toml_str).expect("should parse");
        assert_eq!(cfg.relay.as_deref(), Some("wss://test.example.com/ws"));
        assert_eq!(
            cfg.keyfile.as_deref(),
            Some(std::path::Path::new("/tmp/test.key"))
        );
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
        assert_eq!(cfg.proxy.as_deref(), Some("socks5h://127.0.0.1:9050"));
        assert_eq!(cfg.on_message_hook.as_deref(), Some("/usr/bin/notify"));
        assert_eq!(cfg.auto_payment_address, Some(true));
    }

    #[test]
    fn test_empty_toml_returns_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        let cfg: BotConfig = toml::from_str("").expect("empty toml should parse");
        assert!(cfg.relay.is_none());
        assert!(cfg.keyfile.is_none());
        assert!(cfg.log_level.is_none());
        assert!(cfg.proxy.is_none());
        assert!(cfg.on_message_hook.is_none());
        assert_eq!(cfg.auto_payment_address, None);

        let resolved = resolve_defaults(cfg).expect("resolve should succeed");
        assert_eq!(resolved.relay, "ws://127.0.0.1:3210/ws");
    }

    #[test]
    fn test_env_relay_overrides_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Set the env var, resolve, then unset — even if the assert panics we
        // want to clean up, so we capture the result before asserting.
        unsafe {
            std::env::set_var("RELAY", "wss://env.example.com/ws");
        }
        let file = BotConfig {
            relay: Some("wss://file.example.com/ws".to_string()),
            ..Default::default()
        };
        let result = resolve_defaults(file);
        unsafe {
            std::env::remove_var("RELAY");
        }
        let resolved = result.expect("resolve should succeed");
        assert_eq!(resolved.relay, "wss://env.example.com/ws");
    }

    #[test]
    fn test_invalid_relay_scheme_returns_err() {
        let result = resolve(
            Some("ftp://bad.example.com/ws".to_string()),
            None,
            None,
            None,
            None,
            false,
            false,
            false,
            false,
            None,
            BotConfig::default(),
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("ws://") || msg.contains("relay URL"),
            "error message was: {msg}"
        );
    }

    #[test]
    fn test_missing_keyfile_uses_default() {
        let resolved = resolve(
            None,
            None,
            Some("/tmp/test_data_dir".to_string()),
            None,
            None,
            false,
            false,
            false,
            false,
            None,
            BotConfig::default(),
        )
        .expect("resolve should succeed");

        let keyfile_str = resolved.keyfile.to_string_lossy();
        assert!(
            keyfile_str.ends_with("identity.key"),
            "keyfile should end with identity.key, got: {keyfile_str}"
        );
        assert!(
            keyfile_str.starts_with("/tmp/test_data_dir/"),
            "keyfile should be under /tmp/test_data_dir/, got: {keyfile_str}"
        );
    }
}
