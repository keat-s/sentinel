//! Key generation, storage, and loading for the audit signer.
//!
//! Keys are hex-encoded on disk: the 32-byte ed25519 seed in the secret file
//! (created with `0600` permissions on Unix) and the 32-byte public key in a
//! sibling `.pub` file that can be shipped to whoever needs to verify logs.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Errors from key generation, storage, or loading.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Filesystem failure.
    #[error("key file I/O: {0}")]
    Io(#[from] std::io::Error),
    /// File contents are not valid hex of the right length.
    #[error("malformed key file `{path}`: {detail}")]
    Malformed {
        /// Offending file.
        path: String,
        /// What was wrong.
        detail: String,
    },
}

/// Generate a fresh ed25519 signing key from the OS RNG.
pub fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

/// Write the secret seed to `secret_path` (mode `0600` on Unix) and the
/// public key to `public_path`.
pub fn save_keypair(
    key: &SigningKey,
    secret_path: &Path,
    public_path: &Path,
) -> Result<(), KeyError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(secret_path)?;
    f.write_all(hex::encode(key.to_bytes()).as_bytes())?;
    f.write_all(b"\n")?;

    fs::write(
        public_path,
        format!("{}\n", hex::encode(key.verifying_key().to_bytes())),
    )?;
    Ok(())
}

/// Load a signing key from a hex seed file written by [`save_keypair`].
pub fn load_secret_key(path: &Path) -> Result<SigningKey, KeyError> {
    let text = fs::read_to_string(path)?;
    let bytes = decode32(path, text.trim())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Load a verifying (public) key from a hex file written by [`save_keypair`].
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, KeyError> {
    let text = fs::read_to_string(path)?;
    let bytes = decode32(path, text.trim())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| KeyError::Malformed {
        path: path.display().to_string(),
        detail: format!("not a valid ed25519 public key: {e}"),
    })
}

/// Short stable identifier for a public key: first 8 bytes of its SHA-256,
/// hex-encoded. Recorded on every log entry so rotated keys stay attributable.
pub fn key_id(vk: &VerifyingKey) -> String {
    let digest = Sha256::digest(vk.to_bytes());
    hex::encode(&digest[..8])
}

fn decode32(path: &Path, hex_text: &str) -> Result<[u8; 32], KeyError> {
    let raw = hex::decode(hex_text).map_err(|e| KeyError::Malformed {
        path: path.display().to_string(),
        detail: format!("invalid hex: {e}"),
    })?;
    raw.try_into().map_err(|_| KeyError::Malformed {
        path: path.display().to_string(),
        detail: "expected 32 bytes".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("audit.key");
        let pk_path = dir.path().join("audit.key.pub");
        let key = generate_signing_key();
        save_keypair(&key, &sk_path, &pk_path).unwrap();

        let loaded = load_secret_key(&sk_path).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
        let vk = load_verifying_key(&pk_path).unwrap();
        assert_eq!(vk, key.verifying_key());
        assert_eq!(key_id(&vk).len(), 16);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_private() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("audit.key");
        let pk_path = dir.path().join("audit.key.pub");
        save_keypair(&generate_signing_key(), &sk_path, &pk_path).unwrap();
        let mode = std::fs::metadata(&sk_path).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_to_overwrite_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("audit.key");
        let pk_path = dir.path().join("audit.key.pub");
        save_keypair(&generate_signing_key(), &sk_path, &pk_path).unwrap();
        assert!(save_keypair(&generate_signing_key(), &sk_path, &pk_path).is_err());
    }
}
