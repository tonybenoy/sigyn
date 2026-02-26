use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::keys::{KeyFingerprint, SigningKeyPair, VerifyingKeyWrapper};

/// Default transfer expiry: 7 days.
const TRANSFER_EXPIRY_HOURS: i64 = 7 * 24;

/// A pending ownership transfer record, signed by the old owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransfer {
    pub vault_id: Uuid,
    pub vault_name: String,
    pub from_owner: KeyFingerprint,
    pub to_owner: KeyFingerprint,
    /// Role to assign to old owner after transfer (e.g. Admin). None = remove.
    pub downgrade_role: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Ed25519 signature over the signing payload.
    pub signature: Vec<u8>,
}

impl PendingTransfer {
    /// Build the canonical bytes that are signed/verified.
    ///
    /// Includes all mutable fields with length prefixes to prevent
    /// field-boundary ambiguity and tampering.
    pub fn signing_payload(
        vault_id: Uuid,
        vault_name: &str,
        from_owner: &KeyFingerprint,
        to_owner: &KeyFingerprint,
        downgrade_role: &Option<String>,
        created_at: &chrono::DateTime<chrono::Utc>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"sigyn-transfer-v1:");
        payload.extend_from_slice(vault_id.as_bytes());
        // Length-prefixed vault name to prevent boundary ambiguity
        let name_bytes = vault_name.as_bytes();
        payload.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(name_bytes);
        payload.extend_from_slice(&from_owner.0);
        payload.extend_from_slice(&to_owner.0);
        // Include downgrade_role so it can't be tampered with
        match downgrade_role {
            Some(role) => {
                payload.push(1);
                let role_bytes = role.as_bytes();
                payload.extend_from_slice(&(role_bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(role_bytes);
            }
            None => payload.push(0),
        }
        // Include created_at to prevent replay of stale transfers
        payload.extend_from_slice(&created_at.timestamp().to_le_bytes());
        payload
    }

    /// Sign the transfer with the old owner's signing key.
    pub fn sign(
        vault_id: Uuid,
        vault_name: &str,
        from_owner: &KeyFingerprint,
        to_owner: &KeyFingerprint,
        downgrade_role: Option<String>,
        signing_key: &SigningKeyPair,
    ) -> Self {
        let created_at = chrono::Utc::now();
        let payload = Self::signing_payload(
            vault_id,
            vault_name,
            from_owner,
            to_owner,
            &downgrade_role,
            &created_at,
        );
        let signature = signing_key.sign(&payload);
        Self {
            vault_id,
            vault_name: vault_name.to_string(),
            from_owner: from_owner.clone(),
            to_owner: to_owner.clone(),
            downgrade_role,
            created_at,
            signature,
        }
    }

    /// Verify the old owner's signature.
    pub fn verify(&self, verifying_key: &VerifyingKeyWrapper) -> crate::error::Result<()> {
        let payload = Self::signing_payload(
            self.vault_id,
            &self.vault_name,
            &self.from_owner,
            &self.to_owner,
            &self.downgrade_role,
            &self.created_at,
        );
        verifying_key.verify(&payload, &self.signature)
    }

    /// Check whether this transfer has expired (default: 7 days).
    pub fn is_expired(&self) -> bool {
        let expiry = self.created_at + chrono::Duration::hours(TRANSFER_EXPIRY_HOURS);
        chrono::Utc::now() > expiry
    }
}
