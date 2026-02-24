use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;
use crate::error::{Result, SigynError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaState {
    /// Base32-encoded TOTP secret
    pub totp_secret: String,
    /// Blake3 hashes of backup codes
    pub backup_codes: Vec<String>,
    /// When MFA was enabled
    pub enabled_at: chrono::DateTime<chrono::Utc>,
}

pub struct MfaStore {
    base_dir: PathBuf,
}

impl MfaStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn mfa_path(&self, fingerprint: &KeyFingerprint) -> PathBuf {
        self.base_dir.join(format!("{}.mfa", fingerprint.to_hex()))
    }

    pub fn exists(&self, fingerprint: &KeyFingerprint) -> bool {
        self.mfa_path(fingerprint).exists()
    }

    /// Save MFA state, encrypted with a key derived from the identity's encryption key.
    /// Uses HKDF-SHA256 with context `b"mfa-state"` to derive a ChaCha20-Poly1305 key.
    pub fn save(
        &self,
        fingerprint: &KeyFingerprint,
        state: &MfaState,
        identity_encryption_key: &[u8; 32],
    ) -> Result<()> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

        let enc_key = derive_mfa_key(identity_encryption_key)?;

        // CBOR serialize
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(state, &mut cbor_buf)
            .map_err(|e| SigynError::CborEncode(e.to_string()))?;

        // Encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|e| SigynError::Encryption(e.to_string()))?;
        let nonce_bytes = crate::crypto::nonce::generate_nonce();
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, cbor_buf.as_slice())
            .map_err(|e| SigynError::Encryption(e.to_string()))?;

        // Write: nonce || ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        std::fs::create_dir_all(&self.base_dir)?;
        std::fs::write(self.mfa_path(fingerprint), output)?;
        Ok(())
    }

    /// Load and decrypt MFA state using the identity's encryption key.
    pub fn load(
        &self,
        fingerprint: &KeyFingerprint,
        identity_encryption_key: &[u8; 32],
    ) -> Result<Option<MfaState>> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

        let path = self.mfa_path(fingerprint);
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        if data.len() < 12 {
            return Err(SigynError::Decryption("MFA file too short".into()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let enc_key = derive_mfa_key(identity_encryption_key)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|e| SigynError::Decryption(e.to_string()))?;
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SigynError::Decryption("failed to decrypt MFA state".into()))?;

        let state: MfaState = ciborium::from_reader(plaintext.as_slice())
            .map_err(|e| SigynError::CborDecode(e.to_string()))?;
        Ok(Some(state))
    }

    pub fn remove(&self, fingerprint: &KeyFingerprint) -> Result<()> {
        let path = self.mfa_path(fingerprint);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Derive a 32-byte encryption key from the identity's X25519 private key bytes
/// using HKDF-SHA256 with info context `b"mfa-state"`.
fn derive_mfa_key(identity_key: &[u8; 32]) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, identity_key);
    let mut okm = [0u8; 32];
    hk.expand(b"mfa-state", &mut okm)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

/// Hash a backup code with blake3 for storage.
pub fn hash_backup_code(code: &str) -> String {
    blake3::hash(code.as_bytes()).to_hex().to_string()
}

/// Verify a backup code against a list of hashed codes.
/// Returns the index of the matching code if found.
pub fn verify_backup_code(code: &str, hashed_codes: &[String]) -> Option<usize> {
    let hash = hash_backup_code(code);
    hashed_codes.iter().position(|h| h == &hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MfaStore::new(dir.path().to_path_buf());
        let fp = KeyFingerprint([1u8; 16]);
        let key = [42u8; 32];

        assert!(!store.exists(&fp));

        let state = MfaState {
            totp_secret: "JBSWY3DPEHPK3PXP".into(),
            backup_codes: vec![hash_backup_code("abcd1234")],
            enabled_at: chrono::Utc::now(),
        };

        store.save(&fp, &state, &key).unwrap();
        assert!(store.exists(&fp));

        let loaded = store.load(&fp, &key).unwrap().unwrap();
        assert_eq!(loaded.totp_secret, state.totp_secret);
        assert_eq!(loaded.backup_codes, state.backup_codes);

        store.remove(&fp).unwrap();
        assert!(!store.exists(&fp));
    }

    #[test]
    fn test_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = MfaStore::new(dir.path().to_path_buf());
        let fp = KeyFingerprint([2u8; 16]);
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];

        let state = MfaState {
            totp_secret: "SECRET".into(),
            backup_codes: vec![],
            enabled_at: chrono::Utc::now(),
        };

        store.save(&fp, &state, &key).unwrap();
        assert!(store.load(&fp, &wrong_key).is_err());
    }

    #[test]
    fn test_backup_code_hashing() {
        let code = "abc12345";
        let hash = hash_backup_code(code);
        assert_eq!(verify_backup_code(code, &[hash.clone()]), Some(0));
        assert_eq!(verify_backup_code("wrong", &[hash]), None);
    }
}
