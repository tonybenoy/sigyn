use crate::crypto::keys::KeyFingerprint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    VaultCreated,
    SecretRead { key: String },
    SecretWritten { key: String },
    SecretDeleted { key: String },
    MemberInvited { fingerprint: KeyFingerprint },
    MemberRevoked { fingerprint: KeyFingerprint },
    PolicyChanged,
    MasterKeyRotated,
    ForkCreated { fork_id: uuid::Uuid },
    EnvironmentCreated { name: String },
    EnvironmentPromoted { source: String, target: String },
    BreakGlassActivated,
    IdentityCreated { fingerprint: KeyFingerprint },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Denied(String),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub actor: KeyFingerprint,
    pub action: AuditAction,
    pub env: Option<String>,
    pub outcome: AuditOutcome,
    pub nonce: [u8; 16],
    pub prev_hash: Option<[u8; 32]>,
    pub entry_hash: [u8; 32],
    pub signature: Vec<u8>,
}
