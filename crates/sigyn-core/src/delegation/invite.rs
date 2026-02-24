use crate::crypto::keys::KeyFingerprint;
#[allow(unused_imports)]
use crate::crypto::keys::X25519PublicKey;
use crate::policy::roles::Role;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: uuid::Uuid,
    pub inviter: KeyFingerprint,
    pub invitee_pubkey: Option<X25519PublicKey>,
    pub proposed_role: Role,
    pub allowed_envs: Vec<String>,
    pub secret_patterns: Vec<String>,
    pub max_delegation_depth: u32,
    pub status: InvitationStatus,
    pub signature: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub token: Option<String>,
}

/// A portable invitation file that can be shared with the invitee.
/// This is a JSON document written to `~/.sigyn/invitations/<uuid>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationFile {
    pub id: uuid::Uuid,
    pub vault_name: String,
    pub vault_id: uuid::Uuid,
    pub inviter_fingerprint: KeyFingerprint,
    pub proposed_role: Role,
    pub allowed_envs: Vec<String>,
    pub secret_patterns: Vec<String>,
    pub max_delegation_depth: u32,
    /// Ed25519 signature from the inviter over the canonical invitation payload.
    pub signature: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl InvitationFile {
    /// Build the canonical bytes that are signed by the inviter.
    #[allow(clippy::too_many_arguments)]
    pub fn signing_payload(
        id: uuid::Uuid,
        vault_name: &str,
        vault_id: uuid::Uuid,
        inviter_fingerprint: &KeyFingerprint,
        proposed_role: Role,
        allowed_envs: &[String],
        secret_patterns: &[String],
        max_delegation_depth: u32,
    ) -> Vec<u8> {
        // Deterministic payload: concatenate fields in a stable order.
        let mut payload = Vec::new();
        payload.extend_from_slice(id.as_bytes());
        payload.extend_from_slice(vault_name.as_bytes());
        payload.extend_from_slice(vault_id.as_bytes());
        payload.extend_from_slice(&inviter_fingerprint.0);
        payload.extend_from_slice(proposed_role.to_string().as_bytes());
        for env in allowed_envs {
            payload.extend_from_slice(env.as_bytes());
        }
        for pattern in secret_patterns {
            payload.extend_from_slice(pattern.as_bytes());
        }
        payload.extend_from_slice(&max_delegation_depth.to_le_bytes());
        payload
    }

    /// Verify this invitation file's signature against the inviter's verifying key.
    pub fn verify(
        &self,
        verifying_key: &crate::crypto::keys::VerifyingKeyWrapper,
    ) -> crate::error::Result<()> {
        let payload = Self::signing_payload(
            self.id,
            &self.vault_name,
            self.vault_id,
            &self.inviter_fingerprint,
            self.proposed_role,
            &self.allowed_envs,
            &self.secret_patterns,
            self.max_delegation_depth,
        );
        verifying_key.verify(&payload, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SigningKeyPair;

    #[test]
    fn test_signing_payload_determinism() {
        let id = uuid::Uuid::new_v4();
        let vault_id = uuid::Uuid::new_v4();
        let fp = KeyFingerprint([0xAA; 16]);
        let envs = vec!["dev".to_string(), "prod".to_string()];
        let patterns = vec!["*".to_string()];

        let p1 = InvitationFile::signing_payload(
            id,
            "vault",
            vault_id,
            &fp,
            Role::Contributor,
            &envs,
            &patterns,
            2,
        );
        let p2 = InvitationFile::signing_payload(
            id,
            "vault",
            vault_id,
            &fp,
            Role::Contributor,
            &envs,
            &patterns,
            2,
        );
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_signing_payload_varies_with_input() {
        let id = uuid::Uuid::new_v4();
        let vault_id = uuid::Uuid::new_v4();
        let fp = KeyFingerprint([0xAA; 16]);
        let envs = vec!["dev".to_string()];
        let patterns = vec![];

        let p1 = InvitationFile::signing_payload(
            id,
            "vault-a",
            vault_id,
            &fp,
            Role::Contributor,
            &envs,
            &patterns,
            2,
        );
        let p2 = InvitationFile::signing_payload(
            id,
            "vault-b",
            vault_id,
            &fp,
            Role::Contributor,
            &envs,
            &patterns,
            2,
        );
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let kp = SigningKeyPair::generate();
        let id = uuid::Uuid::new_v4();
        let vault_id = uuid::Uuid::new_v4();
        let fp = KeyFingerprint([0xBB; 16]);
        let envs = vec!["dev".to_string()];
        let patterns = vec!["DB_*".to_string()];

        let payload = InvitationFile::signing_payload(
            id,
            "myvault",
            vault_id,
            &fp,
            Role::Admin,
            &envs,
            &patterns,
            3,
        );
        let signature = kp.sign(&payload);

        let invite = InvitationFile {
            id,
            vault_name: "myvault".to_string(),
            vault_id,
            inviter_fingerprint: fp,
            proposed_role: Role::Admin,
            allowed_envs: envs,
            secret_patterns: patterns,
            max_delegation_depth: 3,
            signature,
            created_at: chrono::Utc::now(),
        };

        assert!(invite.verify(&kp.verifying_key()).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let kp = SigningKeyPair::generate();
        let other_kp = SigningKeyPair::generate();
        let id = uuid::Uuid::new_v4();
        let vault_id = uuid::Uuid::new_v4();
        let fp = KeyFingerprint([0xCC; 16]);

        let payload =
            InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::ReadOnly, &[], &[], 0);
        let signature = kp.sign(&payload);

        let invite = InvitationFile {
            id,
            vault_name: "v".to_string(),
            vault_id,
            inviter_fingerprint: fp,
            proposed_role: Role::ReadOnly,
            allowed_envs: vec![],
            secret_patterns: vec![],
            max_delegation_depth: 0,
            signature,
            created_at: chrono::Utc::now(),
        };

        // Verify with wrong key should fail
        assert!(invite.verify(&other_kp.verifying_key()).is_err());
    }
}
