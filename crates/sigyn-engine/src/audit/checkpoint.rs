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

/// Status of a device-local audit tip check (see [`verify_and_advance_local_tip`]).
#[derive(Debug, Clone, Copy)]
pub struct LocalTipStatus {
    /// Tip recorded on this device before the check, if any.
    pub previous: Option<(u64, [u8; 32])>,
    /// Current chain head after the check (also the newly recorded tip).
    pub current: Option<(u64, [u8; 32])>,
}

/// Verify the device-local audit tip for `vault_name` against the on-disk log,
/// then advance the tip to the current chain head.
///
/// The tip `(sequence, entry_hash)` is stored in the device-local pinned-vaults
/// store (`~/.sigyn/pinned_vaults.cbor`, encrypted with the device key). That
/// file never syncs through the vault's git repo, so an attacker who rewrites
/// or truncates the shared audit log cannot also rewrite the tip.
///
/// The tip is a monotonic low-water mark: other vault members append entries
/// too, so the check only requires that the chain still *contains* the recorded
/// `(sequence, entry_hash)` with no gaps before it. Tail truncation (removing
/// the last N entries, which leaves an otherwise-valid prefix) is detected
/// because the recorded tip entry disappears.
///
/// Returns `Err(AuditChainBroken)` if a recorded tip is no longer present in
/// the log (truncation/deletion), or the underlying I/O/crypto error.
pub fn verify_and_advance_local_tip(
    sigyn_home: &Path,
    vault_name: &str,
    audit_path: &Path,
    audit_cipher: &sigyn_core::crypto::VaultCipher,
) -> Result<LocalTipStatus> {
    let device_key = crate::device::load_or_create_device_key(sigyn_home)?;
    let mut store = crate::vault::local_state::load_pinned_store(sigyn_home, &device_key)?;

    let previous = store
        .get(vault_name)
        .and_then(|s| s.checkpoint.as_ref())
        .and_then(|c| match (c.audit_sequence, c.audit_tip_hash) {
            (Some(seq), Some(hash)) => Some((seq, hash)),
            _ => None,
        });

    // If a tip was recorded, the log must still contain that exact entry (and
    // every sequence before it). This is what makes tail truncation detectable.
    if let Some((seq, hash)) = previous {
        crate::audit::chain::verify_audit_continuity(audit_path, audit_cipher, seq, hash)?;
    }

    // Advance the low-water mark to the current chain head (never regress).
    let current = crate::audit::chain::chain_tip(audit_path, audit_cipher)?;
    if let Some((seq, hash)) = current {
        if previous.is_none_or(|(prev_seq, _)| seq >= prev_seq) {
            let state = store.entry_mut(vault_name);
            let cp = state.checkpoint.get_or_insert_with(Default::default);
            cp.audit_sequence = Some(seq);
            cp.audit_tip_hash = Some(hash);
            crate::vault::local_state::save_pinned_store(&store, sigyn_home, &device_key)?;
        }
    }

    Ok(LocalTipStatus { previous, current })
}

/// Record `(sequence, entry_hash)` as the device-local audit tip for
/// `vault_name`, e.g. right after appending an entry. Monotonic: an older
/// sequence never overwrites a newer recorded tip.
pub fn record_local_tip(
    sigyn_home: &Path,
    vault_name: &str,
    sequence: u64,
    entry_hash: [u8; 32],
) -> Result<()> {
    let device_key = crate::device::load_or_create_device_key(sigyn_home)?;
    let mut store = crate::vault::local_state::load_pinned_store(sigyn_home, &device_key)?;
    let state = store.entry_mut(vault_name);
    let cp = state.checkpoint.get_or_insert_with(Default::default);
    if let Some(prev) = cp.audit_sequence {
        if sequence < prev {
            return Ok(());
        }
    }
    cp.audit_sequence = Some(sequence);
    cp.audit_tip_hash = Some(entry_hash);
    crate::vault::local_state::save_pinned_store(&store, sigyn_home, &device_key)
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
