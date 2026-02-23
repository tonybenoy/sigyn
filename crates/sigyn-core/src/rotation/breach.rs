use crate::crypto::keys::KeyFingerprint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachModeConfig {
    pub rotate_all_secrets: bool,
    pub revoke_all_delegated: bool,
    pub lock_vault: bool,
    pub notify_owner: bool,
}

impl Default for BreachModeConfig {
    fn default() -> Self {
        Self {
            rotate_all_secrets: true,
            revoke_all_delegated: true,
            lock_vault: true,
            notify_owner: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReport {
    pub rotated_keys: Vec<String>,
    pub revoked_members: Vec<KeyFingerprint>,
    pub new_master_key: bool,
    pub vault_locked: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
