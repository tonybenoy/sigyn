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
        }
    }

    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(|e| crate::SigynError::Serialization(e.to_string()))
    }

    pub fn from_toml(s: &str) -> crate::Result<Self> {
        toml::from_str(s).map_err(|e| crate::SigynError::Deserialization(e.to_string()))
    }
}
