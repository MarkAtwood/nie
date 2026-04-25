use std::io::{Read, Write};

use age::secrecy::Secret;
use age::{Decryptor, Encryptor};
use anyhow::{bail, Result};
use zeroize::Zeroizing;

use crate::identity::Identity;

/// Load an identity from an age-encrypted keyfile on disk.
///
/// If `no_passphrase` is true, the empty string is used as the passphrase
/// (caller emits a warning before calling this).
pub fn load_identity(keyfile_path: &str, no_passphrase: bool) -> Result<Identity> {
    if !std::path::Path::new(keyfile_path).exists() {
        bail!("no keyfile at {keyfile_path}. Run `nie init` first.");
    }
    let ciphertext = std::fs::read(keyfile_path)?;

    let passphrase: Zeroizing<String> = if no_passphrase {
        eprintln!("WARNING: --no-passphrase set. Loading identity without encryption.");
        Zeroizing::new(String::new())
    } else {
        Zeroizing::new(rpassword::prompt_password("Passphrase: ")?)
    };

    let seed = decrypt_keyfile(&ciphertext, &passphrase)?;
    let identity = Identity::from_secret_bytes(&seed);
    identity
}

/// Encrypt the 64-byte keyfile payload (Ed25519_seed || X25519_seed) with a
/// passphrase using the age format.
pub fn encrypt_keyfile(seed: &[u8; 64], passphrase: &str) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
    let mut output = vec![];
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| anyhow::anyhow!("age encrypt error: {e}"))?;
    writer.write_all(seed)?;
    writer
        .finish()
        .map_err(|e| anyhow::anyhow!("age finish error: {e}"))?;
    Ok(output)
}

/// Decrypt an age-encrypted keyfile and return the 64-byte payload
/// (Ed25519_seed || X25519_seed).
pub fn decrypt_keyfile(ciphertext: &[u8], passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    if ciphertext.is_empty() {
        bail!("keyfile is empty");
    }
    let decryptor = Decryptor::new(ciphertext)
        .map_err(|e| anyhow::anyhow!("keyfile corrupt or unrecognized format: {e}"))?;
    let pass_decryptor = match decryptor {
        Decryptor::Passphrase(d) => d,
        _ => bail!("keyfile was not encrypted with a passphrase"),
    };
    let mut reader = pass_decryptor
        .decrypt(&Secret::new(passphrase.to_owned()), None)
        .map_err(|_| anyhow::anyhow!("wrong passphrase or corrupt keyfile"))?;
    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(vec![]);
    reader.read_to_end(&mut plaintext)?;
    let len = plaintext.len();
    if len != 64 {
        return Err(anyhow::anyhow!(
            "keyfile corrupt: expected 64 bytes, got {len}"
        ));
    }
    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_keyfile_roundtrip_no_passphrase() {
        let original = Identity::generate();
        let original_pub_id = original.pub_id();

        // Obtain the 64-byte seed (Ed25519_seed || X25519_seed) from the identity
        let seed = original.to_secret_bytes_64();

        // Encrypt with empty passphrase (no_passphrase path)
        let ciphertext = encrypt_keyfile(&seed, "").expect("encrypt_keyfile failed");

        // Decrypt and reconstruct
        let recovered_seed = decrypt_keyfile(&ciphertext, "").expect("decrypt_keyfile failed");
        let recovered = Identity::from_secret_bytes(&recovered_seed).expect("recovered seed must be valid");


        assert_eq!(
            original_pub_id.0,
            recovered.pub_id().0,
            "recovered identity pub_id must match original"
        );
    }

    #[test]
    fn test_decrypt_keyfile_empty_ciphertext() {
        let err = decrypt_keyfile(&[], "pass").unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected 'empty' in error, got: {err}"
        );
    }

    #[test]
    fn test_decrypt_keyfile_wrong_passphrase() {
        let seed = Identity::generate().to_secret_bytes_64();
        let ciphertext = encrypt_keyfile(&seed, "correct").expect("encrypt_keyfile failed");
        let err = decrypt_keyfile(&ciphertext, "wrong").unwrap_err();
        assert!(
            err.to_string().contains("wrong passphrase") || err.to_string().contains("corrupt"),
            "expected passphrase error, got: {err}"
        );
    }
}
