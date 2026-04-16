use std::collections::HashMap;
use std::path::Path;

use tracing::warn;

pub const MAX_KEYS: usize = 32;
pub const MAX_KEY_BYTES: usize = 32;
pub const MAX_VALUE_BYTES: usize = 256;
pub const MAX_TOTAL_BYTES: usize = 4096;

/// Validate a profile map before broadcasting.
/// Returns `Ok(())` if the profile is within limits, `Err(reason)` otherwise.
pub fn validate(profile: &HashMap<String, String>) -> Result<(), String> {
    if profile.len() > MAX_KEYS {
        return Err(format!("too many fields ({} > {MAX_KEYS})", profile.len()));
    }
    for (k, v) in profile {
        if k.is_empty() {
            return Err("key must not be empty".to_string());
        }
        if k.len() > MAX_KEY_BYTES {
            return Err(format!(
                "key {k:?} too long ({} > {MAX_KEY_BYTES} bytes)",
                k.len()
            ));
        }
        // Keys must be lowercase alphanumeric or underscore for forward-compat.
        if !k
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!(
                "key {k:?} must contain only lowercase letters, digits, or underscores"
            ));
        }
        if v.len() > MAX_VALUE_BYTES {
            return Err(format!(
                "value for {k:?} too long ({} > {MAX_VALUE_BYTES} bytes)",
                v.len()
            ));
        }
    }
    // serde_json::to_string on HashMap<String,String> cannot fail
    let total = serde_json::to_string(profile).unwrap().len();
    if total > MAX_TOTAL_BYTES {
        return Err(format!(
            "profile too large ({total} > {MAX_TOTAL_BYTES} bytes)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn valid_profile_passes() {
        assert!(validate(&ok(&[("status", "away"), ("fave_hp_char", "Luna")])).is_ok());
    }

    #[test]
    fn uppercase_key_rejected() {
        assert!(validate(&ok(&[("Status", "away")])).is_err());
    }

    #[test]
    fn space_in_key_rejected() {
        assert!(validate(&ok(&[("my key", "v")])).is_err());
    }

    #[test]
    fn key_too_long_rejected() {
        let long_key = "a".repeat(MAX_KEY_BYTES + 1);
        assert!(validate(&ok(&[(&long_key, "v")])).is_err());
    }

    #[test]
    fn value_too_long_rejected() {
        let long_val = "x".repeat(MAX_VALUE_BYTES + 1);
        assert!(validate(&ok(&[("status", &long_val)])).is_err());
    }

    #[test]
    fn too_many_keys_rejected() {
        let pairs: Vec<(String, String)> = (0..=MAX_KEYS)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        let map: HashMap<String, String> = pairs.into_iter().collect();
        assert!(validate(&map).is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let original = ok(&[("gneder", "🏳️‍🌈"), ("blood_type", "B+")]);
        save(dir.path(), &original);
        let loaded = load(dir.path());
        assert_eq!(loaded, original);
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(load(dir.path()).is_empty());
    }
}

/// Load own profile fields from `data_dir/profile.json`.
/// Returns an empty map if the file does not exist or is malformed.
pub fn load(data_dir: &Path) -> HashMap<String, String> {
    let path = data_dir.join("profile.json");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist own profile fields to `data_dir/profile.json`.
/// Logs a warning on write failure; callers do not need to handle errors.
pub fn save(data_dir: &Path, profile: &HashMap<String, String>) {
    let path = data_dir.join("profile.json");
    // serde_json::to_string_pretty on HashMap<String,String> cannot fail
    let json = serde_json::to_string_pretty(profile).unwrap();
    if let Err(e) = std::fs::write(&path, json) {
        warn!("failed to save profile.json: {e}");
    }
}
