use serde::{Deserialize, Serialize};
use crate::crypto::keys::KeyFingerprint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkMode {
    Leashed,
    Unleashed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkStatus {
    Active,
    Expired,
    Revoked,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkSharingPolicy {
    Private,
    SharedWithParent,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkPolicy {
    pub sharing: ForkSharingPolicy,
    pub max_drift_days: Option<u32>,
    pub inherit_revocations: bool,
    pub allow_new_members: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fork {
    pub id: uuid::Uuid,
    pub parent_vault_id: uuid::Uuid,
    pub fork_vault_id: uuid::Uuid,
    pub mode: ForkMode,
    pub status: ForkStatus,
    pub policy: ForkPolicy,
    pub created_by: KeyFingerprint,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
