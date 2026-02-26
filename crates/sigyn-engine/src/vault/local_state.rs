use std::path::Path;

use sigyn_core::crypto::sealed::{derive_file_cipher, sealed_decrypt, sealed_encrypt};
use sigyn_core::error::{Result, SigynError};
use sigyn_core::vault::local_state::PinnedVaultsStore;

const PINNED_VAULTS_FILE: &str = "pinned_vaults.cbor";
const HKDF_CONTEXT: &[u8] = b"sigyn-pinned-vaults-v1";
const AAD: &[u8] = b"pinned_vaults.cbor";

/// Load the pinned vaults store from `sigyn_home/pinned_vaults.cbor`,
/// decrypting with a cipher derived from the device key.
/// Returns an empty store if the file does not exist.
pub fn load_pinned_store(sigyn_home: &Path, device_key: &[u8; 32]) -> Result<PinnedVaultsStore> {
    let path = sigyn_home.join(PINNED_VAULTS_FILE);
    if !path.exists() {
        return Ok(PinnedVaultsStore::new());
    }
    let data = std::fs::read(&path)?;
    let cipher = derive_file_cipher(device_key, HKDF_CONTEXT)?;
    let plaintext = sealed_decrypt(&cipher, &data, AAD)?;
    let store: PinnedVaultsStore =
        ciborium::from_reader(&plaintext[..]).map_err(|e| SigynError::CborDecode(e.to_string()))?;
    Ok(store)
}

/// Save the pinned vaults store to `sigyn_home/pinned_vaults.cbor`,
/// encrypting with a cipher derived from the device key.
pub fn save_pinned_store(
    store: &PinnedVaultsStore,
    sigyn_home: &Path,
    device_key: &[u8; 32],
) -> Result<()> {
    let path = sigyn_home.join(PINNED_VAULTS_FILE);
    let mut buf = Vec::new();
    ciborium::into_writer(store, &mut buf).map_err(|e| SigynError::CborEncode(e.to_string()))?;
    let cipher = derive_file_cipher(device_key, HKDF_CONTEXT)?;
    let sealed = sealed_encrypt(&cipher, &buf, AAD)?;
    crate::io::atomic_write(&path, &sealed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::vault::local_state::{VaultPin, VaultSyncCheckpoint};

    fn test_device_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_roundtrip_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_device_key();
        let store = PinnedVaultsStore::new();
        save_pinned_store(&store, dir.path(), &key).unwrap();

        let loaded = load_pinned_store(dir.path(), &key).unwrap();
        assert!(loaded.vaults.is_empty());
    }

    #[test]
    fn test_roundtrip_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_device_key();

        let mut store = PinnedVaultsStore::new();
        let state = store.entry_mut("myapp");
        state.pin = Some(VaultPin {
            vault_id: uuid::Uuid::new_v4(),
            owner_fingerprint: sigyn_core::crypto::keys::KeyFingerprint([0xAA; 16]),
            owner_signing_pubkey_bytes: vec![0xBB; 32],
            pinned_at: chrono::Utc::now(),
        });
        state.checkpoint = Some(VaultSyncCheckpoint {
            vault_commit_oid: Some("abc123".into()),
            audit_commit_oid: None,
            audit_sequence: Some(42),
            audit_tip_hash: Some([0xCC; 32]),
        });

        save_pinned_store(&store, dir.path(), &key).unwrap();
        let loaded = load_pinned_store(dir.path(), &key).unwrap();

        let loaded_state = loaded.get("myapp").unwrap();
        assert!(loaded_state.pin.is_some());
        let pin = loaded_state.pin.as_ref().unwrap();
        assert_eq!(pin.owner_fingerprint.0, [0xAA; 16]);
        let cp = loaded_state.checkpoint.as_ref().unwrap();
        assert_eq!(cp.vault_commit_oid.as_deref(), Some("abc123"));
        assert_eq!(cp.audit_sequence, Some(42));
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_device_key();
        let store = load_pinned_store(dir.path(), &key).unwrap();
        assert!(store.vaults.is_empty());
    }

    #[test]
    fn test_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_device_key();
        let store = PinnedVaultsStore::new();
        save_pinned_store(&store, dir.path(), &key).unwrap();

        let wrong_key = [0x99u8; 32];
        assert!(load_pinned_store(dir.path(), &wrong_key).is_err());
    }
}
