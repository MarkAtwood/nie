use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Returns (creating if needed) `$XDG_DATA_HOME/nie` or `~/.local/share/nie`.
pub fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("nie");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Returns `$XDG_CONFIG_HOME/nie` or `~/.config/nie`.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("nie");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Persistent user configuration. Loaded from `<config_dir>/config.toml`.
/// All fields are optional — missing fields fall back to compiled defaults.
///
/// Example config.toml:
///   relay = "wss://relay.example.com/ws"
///   # lightwalletd defaults to the testnet endpoint; only set this to override.
///   lightwalletd = "https://lightwalletd.testnet.z.cash:443"
///   # Route relay connection through a SOCKS5 proxy (e.g. Tor).
///   proxy = "socks5h://127.0.0.1:9050"
#[derive(Debug, Default, Deserialize)]
pub struct AppConfig {
    /// Relay WebSocket URL. Overridden by the --relay CLI flag.
    pub relay: Option<String>,
    /// lightwalletd gRPC endpoint URL. Overridden by the --lightwalletd CLI flag.
    pub lightwalletd: Option<String>,
    /// SOCKS5 proxy URL for relay connection (e.g. `socks5h://127.0.0.1:9050`).
    /// socks5h:// is recommended for .onion addresses (proxy resolves DNS).
    pub proxy: Option<String>,
}

impl AppConfig {
    /// Load from `config_dir/config.toml`. Returns default if the file does
    /// not exist. Returns an error only for parse failures.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        let cfg: Self =
            toml::from_str(&raw).map_err(|e| anyhow::anyhow!("config.toml parse error: {e}"))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_field_deserializes() {
        let toml_str = r#"proxy = "socks5h://127.0.0.1:9050""#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.proxy, Some("socks5h://127.0.0.1:9050".to_string()));
    }

    #[test]
    fn proxy_field_absent_is_none() {
        let toml_str = r#"relay = "ws://localhost:3210/ws""#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.proxy, None);
    }
}

// Contact book is preserved for future DM phases; CLI commands removed in broadcast redesign.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub pubkey: String,
}

#[allow(dead_code)]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    pub entries: Vec<Contact>,
}

#[allow(dead_code)]
impl Contacts {
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("contacts.json");
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&raw)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join("contacts.json");
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Upsert by name.
    pub fn add(&mut self, name: String, pubkey: String) {
        self.entries.retain(|c| c.name != name);
        self.entries.push(Contact { name, pubkey });
    }

    /// Resolve a contact name or raw pubkey string to a pubkey string.
    /// Returns None only if the input looks like a short name but isn't found.
    pub fn resolve(&self, name_or_key: &str) -> Option<String> {
        for c in &self.entries {
            if c.name == name_or_key {
                return Some(c.pubkey.clone());
            }
        }
        // Treat as a raw pubkey only if it is exactly 64 lowercase hex characters.
        // A pubkey is hex(SHA-256(ed25519_verifying_key)) — always 64 chars.
        if name_or_key.len() == 64
            && name_or_key
                .chars()
                .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase())
        {
            Some(name_or_key.to_string())
        } else {
            None
        }
    }
}
