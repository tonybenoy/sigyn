use crate::crypto::keys::KeyFingerprint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    VaultCreated,
    SecretRead {
        key: String,
    },
    SecretWritten {
        key: String,
    },
    SecretDeleted {
        key: String,
    },
    MemberInvited {
        fingerprint: KeyFingerprint,
    },
    MemberRevoked {
        fingerprint: KeyFingerprint,
    },
    PolicyChanged,
    MasterKeyRotated,
    ForkCreated {
        fork_id: uuid::Uuid,
    },
    EnvironmentCreated {
        name: String,
    },
    EnvironmentPromoted {
        source: String,
        target: String,
    },
    BreakGlassActivated,
    IdentityCreated {
        fingerprint: KeyFingerprint,
    },
    /// Secrets exported via `sigyn run export`
    SecretsExported {
        env: String,
        format: String,
    },
    /// Secrets injected into a child process via `sigyn run exec`
    SecretsInjected {
        env: String,
        command: String,
    },
    /// Secrets served over a Unix socket via `sigyn run serve`
    SecretsServed {
        env: String,
    },
    /// Secrets listed via `sigyn secret list`
    SecretsListed {
        env: String,
    },
    /// Environment deleted via `sigyn env delete`
    EnvironmentDeleted {
        name: String,
    },
    /// Vault deleted via `sigyn vault delete`
    VaultDeleted {
        vault_id: uuid::Uuid,
    },
    /// Vault exported via `sigyn vault export`
    VaultExported,
    /// Ownership transferred from one identity to another
    OwnershipTransferred {
        from: KeyFingerprint,
        to: KeyFingerprint,
    },
    /// New owner accepted a pending ownership transfer
    OwnershipTransferAccepted {
        by: KeyFingerprint,
    },
    /// Secrets copied between environments (possibly across vaults)
    SecretsCopied {
        keys: Vec<String>,
        from_env: String,
        to_env: String,
    },
}

impl AuditAction {
    /// Short human-readable name for commit messages and logs.
    pub fn short_name(&self) -> &'static str {
        match self {
            AuditAction::VaultCreated => "vault-created",
            AuditAction::SecretRead { .. } => "secret-read",
            AuditAction::SecretWritten { .. } => "secret-written",
            AuditAction::SecretDeleted { .. } => "secret-deleted",
            AuditAction::MemberInvited { .. } => "member-invited",
            AuditAction::MemberRevoked { .. } => "member-revoked",
            AuditAction::PolicyChanged => "policy-changed",
            AuditAction::MasterKeyRotated => "key-rotated",
            AuditAction::ForkCreated { .. } => "fork-created",
            AuditAction::EnvironmentCreated { .. } => "env-created",
            AuditAction::EnvironmentPromoted { .. } => "env-promoted",
            AuditAction::BreakGlassActivated => "break-glass",
            AuditAction::IdentityCreated { .. } => "identity-created",
            AuditAction::SecretsExported { .. } => "secrets-exported",
            AuditAction::SecretsInjected { .. } => "secrets-injected",
            AuditAction::SecretsServed { .. } => "secrets-served",
            AuditAction::SecretsListed { .. } => "secrets-listed",
            AuditAction::EnvironmentDeleted { .. } => "env-deleted",
            AuditAction::VaultDeleted { .. } => "vault-deleted",
            AuditAction::VaultExported => "vault-exported",
            AuditAction::OwnershipTransferred { .. } => "ownership-transferred",
            AuditAction::OwnershipTransferAccepted { .. } => "ownership-accepted",
            AuditAction::SecretsCopied { .. } => "secrets-copied",
        }
    }
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
