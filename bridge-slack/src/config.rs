use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::Path;

/// Bridge configuration loaded from bridge.toml.
///
/// Security note: slack_bot_token and slack_signing_secret are bearer credentials —
/// never log them.  This type intentionally does not derive Debug.
#[derive(Deserialize)]
pub struct BridgeConfig {
    /// nie relay WebSocket URL (ws:// or wss://).
    pub relay_url: String,
    /// Path to the nie identity keyfile for the bridge bot.
    pub keyfile: String,
    /// Slack Bot User OAuth Token (xoxb-...).
    pub slack_bot_token: String,
    /// Slack Signing Secret used to verify incoming event webhook requests.
    pub slack_signing_secret: String,
    /// Slack channel ID to bridge (e.g. C1234567890).
    pub slack_channel_id: String,
    /// Optional prefix shown before nie sender ID in Slack messages.
    pub bridge_prefix: Option<String>,
    /// TCP port the bridge's Slack webhook HTTP server listens on (default 9001).
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

fn default_listen_port() -> u16 {
    9001
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
        if !self.slack_bot_token.starts_with("xoxb-") {
            bail!("slack_bot_token must start with 'xoxb-'");
        }
        if self.slack_signing_secret.is_empty() {
            bail!("slack_signing_secret must not be empty");
        }
        if self.slack_channel_id.is_empty() {
            bail!("slack_channel_id must not be empty");
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
slack_bot_token = "xoxb-test-token"
slack_signing_secret = "abc123def456"
slack_channel_id = "C1234567890"
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.relay_url, "wss://relay.example.com/ws");
        assert_eq!(cfg.listen_port, 9001); // default
        assert!(cfg.bridge_prefix.is_none());
    }

    #[test]
    fn from_toml_accepts_custom_listen_port() {
        let f = write_config(
            r#"
relay_url = "ws://localhost:3210/ws"
keyfile = "/tmp/bridge.key"
slack_bot_token = "xoxb-test"
slack_signing_secret = "secret"
slack_channel_id = "C123"
listen_port = 9002
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.listen_port, 9002);
    }

    #[test]
    fn validate_rejects_bad_relay_url() {
        let f = write_config(
            r#"
relay_url = "http://wrong"
keyfile = "/tmp/bridge.key"
slack_bot_token = "xoxb-test"
slack_signing_secret = "secret"
slack_channel_id = "C123"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else { panic!("expected error") };
        assert!(e.to_string().contains("relay_url"));
    }

    #[test]
    fn validate_rejects_bad_token_prefix() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
slack_bot_token = "xoxa-wrong-type"
slack_signing_secret = "secret"
slack_channel_id = "C123"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else { panic!("expected error") };
        assert!(e.to_string().contains("slack_bot_token"));
    }

    #[test]
    fn validate_rejects_empty_signing_secret() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
slack_bot_token = "xoxb-test"
slack_signing_secret = ""
slack_channel_id = "C123"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else { panic!("expected error") };
        assert!(e.to_string().contains("slack_signing_secret"));
    }
}
