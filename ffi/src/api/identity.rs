use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use nie_core::identity::Identity;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Identity generation and derivation
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 + X25519 identity.
///
/// Returns a base64-encoded 64-byte secret blob: Ed25519_seed(32) || X25519_seed(32).
/// The return value is key material — the caller must store it securely and must
/// never log it.
pub fn generate_identity() -> String {
    let identity = Identity::generate();
    B64.encode(identity.to_secret_bytes_64())
}

/// Derive the public ID from a base64-encoded 64-byte secret.
///
/// The public ID is 64 lowercase hex characters: hex(SHA-256(ed25519_verifying_key)).
/// Returns `Err` if the input is not valid base64 or is not exactly 64 bytes.
pub fn pub_id_from_secret(secret_b64: String) -> Result<String> {
    let bytes = B64
        .decode(&secret_b64)
        .map_err(|e| anyhow!("base64 decode error: {e}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("keyfile corrupt: expected 64 bytes"))?;
    let identity = Identity::from_secret_bytes(&arr)?;
    Ok(identity.pub_id().0)
}

// ---------------------------------------------------------------------------
// Identity persistence (plain file — OS provides storage security on Android)
// ---------------------------------------------------------------------------

/// Save the identity secret to a file at `path`.
///
/// The file contains the raw 64-byte secret (no encryption at this layer).
/// On Android, `path` should be inside `context.filesDir` which is already
/// protected by the Android OS sandbox; the caller must not use external storage.
///
/// This function creates any missing parent directories.
/// Overwrites any existing file at `path`.
/// `secret_b64` must be a valid base64-encoded 64-byte secret.
///
/// # Security note
/// File permissions are not explicitly restricted (uses OS umask).
/// On Android, the app sandbox (`filesDir`) provides isolation.
/// Do not use this function on Linux without ensuring the directory
/// is mode 0700 or the file is explicitly chmoded afterward.
pub fn save_identity_to_file(path: String, secret_b64: String) -> Result<()> {
    let bytes = B64
        .decode(&secret_b64)
        .map_err(|e| anyhow!("base64 decode error: {e}"))?;
    if bytes.len() != 64 {
        return Err(anyhow!("keyfile corrupt: expected 64 bytes"));
    }
    let p = Path::new(&path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| anyhow!("create_dir_all({parent:?}): {e}"))?;
    }
    let tmp = p.with_extension("tmp");
    fs::write(&tmp, &bytes).map_err(|e| anyhow!("write identity tmp file {path:?}: {e}"))?;
    fs::rename(&tmp, p).map_err(|e| anyhow!("rename identity tmp file {path:?}: {e}"))
}

/// Load the identity secret from a file at `path`.
///
/// Returns `Ok(Some(base64_secret))` if the file exists and is valid.
/// Returns `Ok(None)` if the file does not exist (first-run case).
/// Returns `Err` if the file exists but is malformed.
pub fn load_identity_from_file(path: String) -> Result<Option<String>> {
    let p = Path::new(&path);
    let bytes = match fs::read(p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("read identity file {path:?}: {e}")),
    };
    if bytes.len() != 64 {
        return Err(anyhow!(
            "identity file at {path:?} is {len} bytes, expected 64",
            len = bytes.len()
        ));
    }
    Ok(Some(B64.encode(&bytes)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_valid_base64_64_bytes() {
        let s = generate_identity();
        let bytes = B64.decode(&s).expect("must be valid base64");
        assert_eq!(bytes.len(), 64, "identity secret must be 64 bytes");
    }

    #[test]
    fn pub_id_from_secret_roundtrip() {
        let s = generate_identity();
        let pub_id = pub_id_from_secret(s.clone()).expect("pub_id_from_secret must succeed");
        assert_eq!(pub_id.len(), 64, "pub_id must be 64 hex chars");
        // Same secret always produces the same pub_id.
        let pub_id2 = pub_id_from_secret(s).expect("pub_id_from_secret must succeed again");
        assert_eq!(pub_id, pub_id2, "pub_id must be deterministic");
    }

    #[test]
    fn pub_id_from_secret_bad_base64_returns_err() {
        let result = pub_id_from_secret("not-valid-base64!!!".to_string());
        assert!(result.is_err(), "bad base64 must return Err");
    }

    #[test]
    fn pub_id_from_secret_wrong_length_returns_err() {
        // 32 bytes is wrong — must be exactly 64.
        let short = B64.encode(&[0u8; 32]);
        let result = pub_id_from_secret(short);
        assert!(result.is_err(), "wrong-length secret must return Err");
    }

    #[test]
    fn save_and_load_identity_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("identity.bin")
            .to_string_lossy()
            .to_string();
        let secret = generate_identity();

        save_identity_to_file(path.clone(), secret.clone()).expect("save must succeed");
        let loaded = load_identity_from_file(path).expect("load must succeed");
        assert_eq!(
            loaded,
            Some(secret),
            "loaded secret must match saved secret"
        );
    }

    #[test]
    fn load_identity_missing_file_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("nonexistent.bin")
            .to_string_lossy()
            .to_string();
        let result = load_identity_from_file(path).expect("load must not error on missing file");
        assert_eq!(result, None, "missing file must return None");
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("a/b/c/identity.bin")
            .to_string_lossy()
            .to_string();
        let secret = generate_identity();
        save_identity_to_file(path.clone(), secret).expect("save must create parent dirs");
        assert!(
            std::path::Path::new(&path).exists(),
            "identity file must exist after save"
        );
    }
}
