use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHistoryEntry {
    pub version: u64,
    pub changed_at: chrono::DateTime<chrono::Utc>,
    pub changed_by: crate::crypto::keys::KeyFingerprint,
    pub value_hash: [u8; 32],
}
