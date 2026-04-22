use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::Path;

/// Bridge configuration loaded from bridge.toml.
///
/// Security note: as_token and hs_token are bearer credentials — never log them.
/// This type intentionally does not derive Debug to prevent accidental logging.
#[derive(Deserialize)]
pub struct BridgeConfig {
    /// nie relay WebSocket URL (ws:// or wss://).
    pub relay_url: String,
    /// Path to the nie identity keyfile for the bridge bot.
    pub keyfile: String,
    /// Matrix homeserver base URL (https://).
    pub matrix_homeserver: String,
    /// Matrix room ID to bridge (e.g. !abc123:example.com).
    pub matrix_room_id: String,
    /// Application Service token — used when calling the Matrix C-S API.
    pub as_token: String,
    /// Homeserver token — verified on incoming AS push requests.
    pub hs_token: String,
    /// Localpart of the bridge bot Matrix user (e.g. "niebridge").
    pub bot_localpart: String,
    /// Optional prefix shown before nie sender ID in Matrix messages.
    pub bridge_prefix: Option<String>,
    /// TCP port the bridge's AS HTTP server listens on (default 9000).
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

fn default_listen_port() -> u16 {
    9000
}

impl BridgeConfig {
    /// Load and validate bridge configuration from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        let config: BridgeConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("config parse error: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if !self.relay_url.starts_with("ws://") && !self.relay_url.starts_with("wss://") {
            bail!("relay_url must start with ws:// or wss://, got: {}", self.relay_url);
        }
        if !self.matrix_homeserver.starts_with("https://") {
            bail!(
                "matrix_homeserver must start with https://, got: {}",
                self.matrix_homeserver
            );
        }
        if !self.matrix_room_id.starts_with('!') {
            bail!(
                "matrix_room_id must start with '!', got: {}",
                self.matrix_room_id
            );
        }
        if self.as_token.is_empty() {
            bail!("as_token must not be empty");
        }
        if self.hs_token.is_empty() {
            bail!("hs_token must not be empty");
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
matrix_homeserver = "https://matrix.example.com"
matrix_room_id = "!abc123:example.com"
as_token = "secret_as"
hs_token = "secret_hs"
bot_localpart = "niebridge"
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.relay_url, "wss://relay.example.com/ws");
        assert_eq!(cfg.listen_port, 9000); // default
        assert!(cfg.bridge_prefix.is_none());
    }

    #[test]
    fn from_toml_accepts_custom_listen_port() {
        let f = write_config(
            r#"
relay_url = "ws://localhost:3210/ws"
keyfile = "/tmp/bridge.key"
matrix_homeserver = "https://matrix.example.com"
matrix_room_id = "!abc:example.com"
as_token = "a"
hs_token = "b"
bot_localpart = "niebridge"
listen_port = 9001
"#,
        );
        let cfg = BridgeConfig::from_toml(f.path()).unwrap();
        assert_eq!(cfg.listen_port, 9001);
    }

    #[test]
    fn validate_rejects_bad_relay_url() {
        let f = write_config(
            r#"
relay_url = "http://wrong"
keyfile = "/tmp/bridge.key"
matrix_homeserver = "https://matrix.example.com"
matrix_room_id = "!abc:example.com"
as_token = "a"
hs_token = "b"
bot_localpart = "niebridge"
"#,
        );
        let result = BridgeConfig::from_toml(f.path());
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("relay_url"));
    }

    #[test]
    fn validate_rejects_bad_room_id() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
matrix_homeserver = "https://matrix.example.com"
matrix_room_id = "not-a-room-id"
as_token = "a"
hs_token = "b"
bot_localpart = "niebridge"
"#,
        );
        let result = BridgeConfig::from_toml(f.path());
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("matrix_room_id"));
    }

    #[test]
    fn validate_rejects_bad_homeserver_url() {
        let f = write_config(
            r#"
relay_url = "wss://relay.example.com/ws"
keyfile = "/tmp/bridge.key"
matrix_homeserver = "http://not-https"
matrix_room_id = "!abc:example.com"
as_token = "a"
hs_token = "b"
bot_localpart = "niebridge"
"#,
        );
        let result = BridgeConfig::from_toml(f.path());
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("matrix_homeserver"));
    }
}
