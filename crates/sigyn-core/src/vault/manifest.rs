use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::keys::KeyFingerprint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    pub vault_id: Uuid,
    pub name: String,
    pub owner: KeyFingerprint,
    pub environments: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub description: Option<String>,
    /// Optional org hierarchy path this vault belongs to, e.g. "acme/platform/web".
    #[serde(default)]
    pub org_path: Option<String>,
}

impl VaultManifest {
    pub fn new(name: String, owner: KeyFingerprint) -> Self {
        Self {
            vault_id: Uuid::new_v4(),
            name,
            owner,
            environments: vec!["dev".into(), "staging".into(), "prod".into()],
            created_at: chrono::Utc::now(),
            description: None,
            org_path: None,
        }
    }

    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(|e| crate::SigynError::Serialization(e.to_string()))
    }

    pub fn from_toml(s: &str) -> crate::Result<Self> {
        toml::from_str(s).map_err(|e| crate::SigynError::Deserialization(e.to_string()))
    }

    /// Serialize to TOML, then encrypt with the sealed file format.
    /// AAD is set to the vault_id bytes for binding.
    pub fn to_sealed_bytes(
        &self,
        cipher: &crate::crypto::vault_cipher::VaultCipher,
    ) -> crate::Result<Vec<u8>> {
        let toml = self.to_toml()?;
        crate::crypto::sealed::sealed_encrypt(cipher, toml.as_bytes(), self.vault_id.as_bytes())
    }

    /// Decrypt sealed bytes back into a VaultManifest.
    /// Requires the SGYN sealed format — plaintext is rejected.
    pub fn from_sealed_bytes(
        cipher: &crate::crypto::vault_cipher::VaultCipher,
        data: &[u8],
        vault_id: Uuid,
    ) -> crate::Result<Self> {
        if !crate::crypto::sealed::is_sealed(data) {
            return Err(crate::SigynError::Decryption(
                "vault manifest is not in sealed format (SGYN) — file may be tampered or corrupted"
                    .into(),
            ));
        }
        let plaintext = crate::crypto::sealed::sealed_decrypt(cipher, data, vault_id.as_bytes())?;
        let s = std::str::from_utf8(&plaintext)
            .map_err(|e| crate::SigynError::Deserialization(e.to_string()))?;
        Self::from_toml(s)
    }
}
