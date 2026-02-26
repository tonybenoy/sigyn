use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sigyn_core::crypto::keys::{SigningKeyPair, VerifyingKeyWrapper};
use sigyn_core::crypto::sealed::{signed_unwrap, signed_wrap};
use sigyn_core::error::{Result, SigynError};

/// An audit checkpoint captures the current state of the audit log at a point
/// in time. It is CBOR-serialized and Ed25519-signed (SGSN format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub sequence: u64,
    pub entry_hash: [u8; 32],
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl AuditCheckpoint {
    /// Write a signed checkpoint to disk.
    pub fn write(&self, path: &Path, signing_key: &SigningKeyPair, vault_id: &Uuid) -> Result<()> {
        let mut cbor = Vec::new();
        ciborium::into_writer(self, &mut cbor)
            .map_err(|e| SigynError::CborEncode(e.to_string()))?;
        let signed = signed_wrap(&cbor, signing_key, vault_id.as_bytes());
        crate::io::atomic_write(path, &signed)
    }

    /// Load and verify a signed checkpoint from disk.
    pub fn load(path: &Path, verifying_key: &VerifyingKeyWrapper, vault_id: &Uuid) -> Result<Self> {
        let data = std::fs::read(path)?;
        let cbor = signed_unwrap(&data, verifying_key, vault_id.as_bytes())?;
        ciborium::from_reader(cbor.as_slice()).map_err(|e| SigynError::CborDecode(e.to_string()))
    }
}

/// Verify that the current audit log state matches the checkpoint.
///
/// Returns `Ok(())` if the log entry at `checkpoint.sequence` has the expected hash.
/// Returns `Err(AuditChainBroken)` if they don't match or the entry is missing.
pub fn verify_against_checkpoint(
    checkpoint: &AuditCheckpoint,
    audit_path: &Path,
    audit_cipher: &sigyn_core::crypto::VaultCipher,
) -> Result<()> {
    crate::audit::chain::verify_audit_continuity(
        audit_path,
        audit_cipher,
        checkpoint.sequence,
        checkpoint.entry_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::crypto::keys::SigningKeyPair;

    #[test]
    fn test_checkpoint_write_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.checkpoint");
        let kp = SigningKeyPair::generate();
        let vk = kp.verifying_key();
        let vault_id = Uuid::new_v4();

        let cp = AuditCheckpoint {
            sequence: 42,
            entry_hash: [0xABu8; 32],
            timestamp: chrono::Utc::now(),
        };

        cp.write(&path, &kp, &vault_id).unwrap();
        let loaded = AuditCheckpoint::load(&path, &vk, &vault_id).unwrap();

        assert_eq!(loaded.sequence, 42);
        assert_eq!(loaded.entry_hash, [0xABu8; 32]);
    }

    #[test]
    fn test_checkpoint_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.checkpoint");
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let cp = AuditCheckpoint {
            sequence: 1,
            entry_hash: [0x00u8; 32],
            timestamp: chrono::Utc::now(),
        };

        cp.write(&path, &kp1, &vault_id).unwrap();
        assert!(AuditCheckpoint::load(&path, &kp2.verifying_key(), &vault_id).is_err());
    }
}
