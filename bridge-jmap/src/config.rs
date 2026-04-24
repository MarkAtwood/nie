use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::Path;

/// Bridge configuration loaded from bridge.toml.
///
/// Security note: jmap_bearer_token is a credential — never log it.
/// This type intentionally does not derive Debug.
#[derive(Deserialize)]
pub struct BridgeConfig {
    /// nie relay WebSocket URL (ws:// or wss://).
    pub relay_url: String,
    /// Path to the nie identity keyfile for the bridge bot.
    pub keyfile: String,
    /// JMAP session URL (e.g. https://jmap.example.com/.well-known/jmap).
    pub jmap_session_url: String,
    /// JMAP Bearer token (API key or OAuth2 access token).
    pub jmap_bearer_token: String,
    /// JMAP account ID to use (from the session response).
    pub jmap_account_id: String,
    /// JMAP mailbox ID to bridge (emails in this mailbox are relayed to nie).
    pub jmap_mailbox_id: String,
    /// Optional display name for the JMAP mailbox in nie messages.
    pub mailbox_name: Option<String>,
    /// Optional prefix shown before nie sender ID in JMAP messages.
    pub bridge_prefix: Option<String>,
    /// Poll interval in seconds (default 30).
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval() -> u64 {
    30
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
        if self.jmap_session_url.starts_with("http://") {
            bail!(
                "JMAP_SESSION_URL uses http:// which would send the bearer token in cleartext; \
                 use https:// instead"
            );
        }
        if !self.jmap_session_url.starts_with("https://") {
            bail!("jmap_session_url must start with https://");
        }
        if self.jmap_bearer_token.is_empty() {
            bail!("jmap_bearer_token must not be empty");
        }
        if self.jmap_account_id.is_empty() {
            bail!("jmap_account_id must not be empty");
        }
        if self.jmap_mailbox_id.is_empty() {
            bail!("jmap_mailbox_id must not be empty");
        }
        if self.poll_interval_secs == 0 {
            bail!("poll_interval_secs must be > 0");
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
jmap_session_url = "https://jmap.example.com/.well-known/jmap"
jmap_bearer_token = "secret-token"
jmap_account_id = "acct-123"
jmap_mailbox_id = "mbox-456"
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.relay_url, "wss://relay.example.com/ws");
        assert_eq!(cfg.poll_interval_secs, 30); // default
        assert!(cfg.bridge_prefix.is_none());
    }

    #[test]
    fn from_toml_accepts_custom_poll_interval() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
jmap_session_url = "https://jmap.example.com/.well-known/jmap"
jmap_bearer_token = "secret"
jmap_account_id = "acct-123"
jmap_mailbox_id = "mbox-456"
poll_interval_secs = 60
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.poll_interval_secs, 60);
    }

    #[test]
    fn validate_rejects_http_jmap_session_url() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
jmap_session_url = "http://jmap.example.com/.well-known/jmap"
jmap_bearer_token = "secret"
jmap_account_id = "acct-123"
jmap_mailbox_id = "mbox-456"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error for http:// jmap_session_url")
        };
        assert!(e.to_string().contains("cleartext"));
    }

    #[test]
    fn validate_rejects_bad_relay_url() {
        let f = write_config(
            r#"
relay_url = "http://wrong"
keyfile = "/tmp/bridge.key"
jmap_session_url = "https://jmap.example.com/.well-known/jmap"
jmap_bearer_token = "secret"
jmap_account_id = "acct-123"
jmap_mailbox_id = "mbox-456"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error")
        };
        assert!(e.to_string().contains("relay_url"));
    }

    #[test]
    fn validate_rejects_empty_bearer_token() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
jmap_session_url = "https://jmap.example.com/.well-known/jmap"
jmap_bearer_token = ""
jmap_account_id = "acct-123"
jmap_mailbox_id = "mbox-456"
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error")
        };
        assert!(e.to_string().contains("jmap_bearer_token"));
    }

    #[test]
    fn validate_rejects_zero_poll_interval() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
jmap_session_url = "https://jmap.example.com/.well-known/jmap"
jmap_bearer_token = "secret"
jmap_account_id = "acct-123"
jmap_mailbox_id = "mbox-456"
poll_interval_secs = 0
"#,
        );
        let Err(e) = BridgeConfig::from_toml(f.path()) else {
            panic!("expected error")
        };
        assert!(e.to_string().contains("poll_interval_secs"));
    }
}
