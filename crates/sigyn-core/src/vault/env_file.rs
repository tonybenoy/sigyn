use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::crypto::vault_cipher::VaultCipher;
use crate::error::{SigynError, Result};
use crate::secrets::types::{SecretEntry, SecretMetadata, SecretValue};

#[derive(Serialize, Deserialize)]
pub struct EncryptedEnvFile {
    pub nonce_and_ciphertext: Vec<u8>,
    pub content_hash: [u8; 32],
    pub env_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextEnv {
    pub entries: IndexMap<String, SecretEntry>,
    pub version: u64,
    pub last_modified_by: Option<crate::crypto::keys::KeyFingerprint>,
    pub last_modified_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl PlaintextEnv {
    pub fn new() -> Self {
        Self {
            entries: IndexMap::new(),
            version: 0,
            last_modified_by: None,
            last_modified_at: None,
        }
    }

    pub fn set(
        &mut self,
        key: String,
        value: SecretValue,
        writer: &crate::crypto::keys::KeyFingerprint,
    ) {
        self.version += 1;
        self.last_modified_by = Some(writer.clone());
        self.last_modified_at = Some(chrono::Utc::now());

        if let Some(existing) = self.entries.get_mut(&key) {
            existing.value = value;
            existing.metadata.version += 1;
            existing.metadata.updated_at = chrono::Utc::now();
            existing.metadata.updated_by = writer.clone();
        } else {
            let metadata = SecretMetadata::new(writer.clone());
            self.entries.insert(
                key.clone(),
                SecretEntry {
                    key,
                    value,
                    metadata,
                },
            );
        }
    }

    pub fn get(&self, key: &str) -> Option<&SecretEntry> {
        self.entries.get(key)
    }

    pub fn remove(&mut self, key: &str) -> Option<SecretEntry> {
        self.version += 1;
        self.entries.shift_remove(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for PlaintextEnv {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encrypt_env(
    env: &PlaintextEnv,
    cipher: &VaultCipher,
    env_name: &str,
) -> Result<EncryptedEnvFile> {
    let mut plaintext_bytes = Vec::new();
    ciborium::into_writer(env, &mut plaintext_bytes)
        .map_err(|e| SigynError::CborEncode(e.to_string()))?;

    let content_hash = blake3::hash(&plaintext_bytes);
    let aad = env_name.as_bytes();
    let nonce_and_ciphertext = cipher.encrypt(&plaintext_bytes, aad)?;

    Ok(EncryptedEnvFile {
        nonce_and_ciphertext,
        content_hash: *content_hash.as_bytes(),
        env_name: env_name.to_string(),
    })
}

pub fn decrypt_env(encrypted: &EncryptedEnvFile, cipher: &VaultCipher) -> Result<PlaintextEnv> {
    let aad = encrypted.env_name.as_bytes();
    let plaintext_bytes = cipher.decrypt(&encrypted.nonce_and_ciphertext, aad)?;

    let actual_hash = blake3::hash(&plaintext_bytes);
    if actual_hash.as_bytes() != &encrypted.content_hash {
        return Err(SigynError::Decryption("content hash mismatch".into()));
    }

    ciborium::from_reader(plaintext_bytes.as_slice())
        .map_err(|e| SigynError::CborDecode(e.to_string()))
}

pub fn write_encrypted_env(path: &Path, env_file: &EncryptedEnvFile) -> Result<()> {
    let mut data = Vec::new();
    ciborium::into_writer(env_file, &mut data)
        .map_err(|e| SigynError::CborEncode(e.to_string()))?;
    atomic_write(path, &data)
}

pub fn read_encrypted_env(path: &Path) -> Result<EncryptedEnvFile> {
    let data = std::fs::read(path)?;
    ciborium::from_reader(data.as_slice()).map_err(|e| SigynError::CborDecode(e.to_string()))
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.persist(path).map_err(|e| SigynError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_env_roundtrip() {
        let cipher = VaultCipher::generate();
        let fp = crate::crypto::keys::KeyFingerprint([0u8; 16]);
        let mut env = PlaintextEnv::new();
        env.set(
            "DB_URL".into(),
            SecretValue::String("postgres://localhost".into()),
            &fp,
        );
        env.set(
            "API_KEY".into(),
            SecretValue::String("sk-test-123".into()),
            &fp,
        );

        let encrypted = encrypt_env(&env, &cipher, "dev").unwrap();
        let decrypted = decrypt_env(&encrypted, &cipher).unwrap();

        assert_eq!(decrypted.entries.len(), 2);
        assert_eq!(
            decrypted.get("DB_URL").unwrap().value,
            SecretValue::String("postgres://localhost".into())
        );
    }

    #[test]
    fn test_plaintext_env_operations() {
        let fp = crate::crypto::keys::KeyFingerprint([1u8; 16]);
        let mut env = PlaintextEnv::new();

        assert!(env.is_empty());
        env.set("KEY1".into(), SecretValue::String("val1".into()), &fp);
        assert_eq!(env.len(), 1);

        env.set("KEY1".into(), SecretValue::String("val2".into()), &fp);
        assert_eq!(env.len(), 1);
        assert_eq!(env.get("KEY1").unwrap().metadata.version, 2);

        env.remove("KEY1");
        assert!(env.is_empty());
    }
}
