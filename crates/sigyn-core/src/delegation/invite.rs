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
    /// When this invitation expires. Default: 7 days from creation.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl InvitationFile {
    /// Build the canonical bytes that are signed by the inviter.
    ///
    /// Format v3: `created_at` and `expires_at` are part of the signed
    /// payload so an invitee cannot extend (or remove) the expiry without
    /// invalidating the signature. Verification fails closed: invitations
    /// signed with the older v2 payload (which did not cover the timestamps)
    /// no longer verify and must be re-issued.
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
        created_at: &chrono::DateTime<chrono::Utc>,
        expires_at: &Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<u8> {
        // Deterministic payload with length-prefixed fields to prevent
        // ambiguity from variable-length concatenation.
        // NOTE: The invitation ID (UUID v4) already makes each invitation unique,
        // preventing replay of the exact same signed payload.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"sigyn-invitation-v3:");
        payload.extend_from_slice(id.as_bytes());
        // Length-prefix all variable-length fields
        let vault_name_bytes = vault_name.as_bytes();
        payload.extend_from_slice(&(vault_name_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(vault_name_bytes);
        payload.extend_from_slice(vault_id.as_bytes());
        payload.extend_from_slice(&inviter_fingerprint.0);
        let role_bytes = proposed_role.to_string();
        payload.extend_from_slice(&(role_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(role_bytes.as_bytes());
        // Encode list count then length-prefixed elements
        payload.extend_from_slice(&(allowed_envs.len() as u32).to_le_bytes());
        for env in allowed_envs {
            let env_bytes = env.as_bytes();
            payload.extend_from_slice(&(env_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(env_bytes);
        }
        payload.extend_from_slice(&(secret_patterns.len() as u32).to_le_bytes());
        for pattern in secret_patterns {
            let pat_bytes = pattern.as_bytes();
            payload.extend_from_slice(&(pat_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(pat_bytes);
        }
        payload.extend_from_slice(&max_delegation_depth.to_le_bytes());
        // Include created_at so it can't be backdated/postdated
        payload.extend_from_slice(&created_at.timestamp().to_le_bytes());
        // Include expires_at (option-tagged, same pattern as vault::transfer)
        // so the invitee cannot null-out or extend the expiry
        match expires_at {
            Some(ts) => {
                payload.push(1);
                payload.extend_from_slice(&ts.timestamp().to_le_bytes());
            }
            None => payload.push(0),
        }
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
            &self.created_at,
            &self.expires_at,
        );
        verifying_key.verify(&payload, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SigningKeyPair;

    /// Helper: build a signed InvitationFile with the given expiry.
    fn signed_invitation(
        kp: &SigningKeyPair,
        created_at: chrono::DateTime<chrono::Utc>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> InvitationFile {
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
            &created_at,
            &expires_at,
        );
        let signature = kp.sign(&payload);

        InvitationFile {
            id,
            vault_name: "myvault".to_string(),
            vault_id,
            inviter_fingerprint: fp,
            proposed_role: Role::Admin,
            allowed_envs: envs,
            secret_patterns: patterns,
            max_delegation_depth: 3,
            signature,
            created_at,
            expires_at,
        }
    }

    #[test]
    fn test_signing_payload_determinism() {
        let id = uuid::Uuid::new_v4();
        let vault_id = uuid::Uuid::new_v4();
        let fp = KeyFingerprint([0xAA; 16]);
        let envs = vec!["dev".to_string(), "prod".to_string()];
        let patterns = vec!["*".to_string()];
        let created = chrono::Utc::now();
        let expires = Some(created + chrono::Duration::days(7));

        let p1 = InvitationFile::signing_payload(
            id,
            "vault",
            vault_id,
            &fp,
            Role::Contributor,
            &envs,
            &patterns,
            2,
            &created,
            &expires,
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
            &created,
            &expires,
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
        let created = chrono::Utc::now();

        let p1 = InvitationFile::signing_payload(
            id,
            "vault-a",
            vault_id,
            &fp,
            Role::Contributor,
            &envs,
            &patterns,
            2,
            &created,
            &None,
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
            &created,
            &None,
        );
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_signing_payload_covers_expiry() {
        let id = uuid::Uuid::new_v4();
        let vault_id = uuid::Uuid::new_v4();
        let fp = KeyFingerprint([0xAA; 16]);
        let created = chrono::Utc::now();
        let expires = Some(created + chrono::Duration::days(7));

        let with_expiry = InvitationFile::signing_payload(
            id,
            "vault",
            vault_id,
            &fp,
            Role::ReadOnly,
            &[],
            &[],
            0,
            &created,
            &expires,
        );
        let without_expiry = InvitationFile::signing_payload(
            id,
            "vault",
            vault_id,
            &fp,
            Role::ReadOnly,
            &[],
            &[],
            0,
            &created,
            &None,
        );
        assert_ne!(with_expiry, without_expiry);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let kp = SigningKeyPair::generate();
        let created = chrono::Utc::now();
        let invite = signed_invitation(&kp, created, Some(created + chrono::Duration::days(7)));
        assert!(invite.verify(&kp.verifying_key()).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let kp = SigningKeyPair::generate();
        let other_kp = SigningKeyPair::generate();
        let invite = signed_invitation(&kp, chrono::Utc::now(), None);

        // Verify with wrong key should fail
        assert!(invite.verify(&other_kp.verifying_key()).is_err());
    }

    #[test]
    fn test_verify_rejects_nulled_expiry() {
        let kp = SigningKeyPair::generate();
        let created = chrono::Utc::now();
        let mut invite = signed_invitation(&kp, created, Some(created + chrono::Duration::days(7)));

        // Invitee strips the expiry to make the invitation immortal
        invite.expires_at = None;
        assert!(invite.verify(&kp.verifying_key()).is_err());
    }

    #[test]
    fn test_verify_rejects_extended_expiry() {
        let kp = SigningKeyPair::generate();
        let created = chrono::Utc::now();
        let mut invite = signed_invitation(&kp, created, Some(created + chrono::Duration::days(7)));

        // Invitee extends the expiry by 10 years
        invite.expires_at = Some(created + chrono::Duration::days(3650));
        assert!(invite.verify(&kp.verifying_key()).is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_created_at() {
        let kp = SigningKeyPair::generate();
        let created = chrono::Utc::now();
        let mut invite = signed_invitation(&kp, created, Some(created + chrono::Duration::days(7)));

        invite.created_at = created + chrono::Duration::days(30);
        assert!(invite.verify(&kp.verifying_key()).is_err());
    }
}
