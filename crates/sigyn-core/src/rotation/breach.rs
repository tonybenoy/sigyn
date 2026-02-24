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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breach_mode_config_default() {
        let config = BreachModeConfig::default();
        assert!(config.rotate_all_secrets);
        assert!(config.revoke_all_delegated);
        assert!(config.lock_vault);
        assert!(config.notify_owner);
    }

    #[test]
    fn test_breach_mode_config_custom() {
        let config = BreachModeConfig {
            rotate_all_secrets: false,
            revoke_all_delegated: true,
            lock_vault: false,
            notify_owner: true,
        };
        assert!(!config.rotate_all_secrets);
        assert!(config.revoke_all_delegated);
        assert!(!config.lock_vault);
        assert!(config.notify_owner);
    }

    #[test]
    fn test_breach_report_fields() {
        let report = BreachReport {
            rotated_keys: vec!["KEY_A".to_string(), "KEY_B".to_string()],
            revoked_members: vec![KeyFingerprint([1u8; 16])],
            new_master_key: true,
            vault_locked: true,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(report.rotated_keys.len(), 2);
        assert_eq!(report.revoked_members.len(), 1);
        assert!(report.new_master_key);
        assert!(report.vault_locked);
    }
}
