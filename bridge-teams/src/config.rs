use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use std::path::Path;

/// Bridge configuration loaded from bridge.toml.
///
/// Security note: teams_security_token and teams_incoming_webhook_url are bearer
/// credentials — never log them.  This type intentionally does not derive Debug.
#[derive(Deserialize)]
pub struct BridgeConfig {
    /// nie relay WebSocket URL (ws:// or wss://).
    pub relay_url: String,
    /// Path to the nie identity keyfile for the bridge bot.
    pub keyfile: String,
    /// Teams outgoing webhook security token (base64-encoded 32-byte key from Teams admin).
    pub teams_security_token: String,
    /// Teams incoming webhook connector URL for posting messages into the Teams channel.
    pub teams_incoming_webhook_url: String,
    /// Optional prefix shown before nie sender ID in Teams messages.
    pub bridge_prefix: Option<String>,
    /// TCP port the bridge's Teams webhook HTTP server listens on (default 9002).
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

fn default_listen_port() -> u16 {
    9002
}

impl BridgeConfig {
    /// Load and validate bridge configuration from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        let config: BridgeConfig =
            toml::from_str(&content).map_err(|e| anyhow::anyhow!("config parse error: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if !self.relay_url.starts_with("ws://") && !self.relay_url.starts_with("wss://") {
            bail!(
                "relay_url must start with ws:// or wss://, got: {}",
                self.relay_url
            );
        }
        if self.teams_security_token.is_empty() {
            bail!("teams_security_token must not be empty");
        }
        B64.decode(&self.teams_security_token).map_err(|e| {
            anyhow::anyhow!("teams_security_token is not valid base64: {e}")
        })?;
        if !self.teams_incoming_webhook_url.starts_with("https://") {
            bail!("teams_incoming_webhook_url must start with https://");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn from_toml_parses_valid_config() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
teams_security_token = "dGVzdHRva2Vu"
teams_incoming_webhook_url = "https://teams.microsoft.com/l/webhook/example"
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.relay_url, "wss://relay.example.com/ws");
        assert_eq!(cfg.listen_port, 9002); // default
        assert!(cfg.bridge_prefix.is_none());
    }

    #[test]
    fn from_toml_accepts_custom_listen_port() {
        let f = write_config(
            r#"
relay_url = "ws://localhost:3210/ws"
keyfile = "/tmp/bridge.key"
teams_security_token = "dGVzdA=="
teams_incoming_webhook_url = "https://teams.microsoft.com/webhook/test"
listen_port = 9003
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.listen_port, 9003);
    }

    #[test]
    fn validate_rejects_bad_relay_url() {
        let f = write_config(
            r#"
relay_url = "http://wrong"
keyfile = "/tmp/bridge.key"
teams_security_token = "dGVzdA=="
teams_incoming_webhook_url = "https://teams.microsoft.com/webhook/test"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error")
        };
        assert!(e.to_string().contains("relay_url"));
    }

    #[test]
    fn validate_rejects_empty_security_token() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
teams_security_token = ""
teams_incoming_webhook_url = "https://teams.microsoft.com/webhook/test"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error")
        };
        assert!(e.to_string().contains("teams_security_token"));
    }

    #[test]
    fn validate_rejects_non_https_webhook_url() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
teams_security_token = "dGVzdA=="
teams_incoming_webhook_url = "http://not-secure.example.com/webhook"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error")
        };
        assert!(e.to_string().contains("teams_incoming_webhook_url"));
    }
}
