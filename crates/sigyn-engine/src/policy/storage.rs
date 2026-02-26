use std::path::Path;

use sigyn_core::crypto::keys::{SigningKeyPair, VerifyingKeyWrapper};

use sigyn_core::crypto::VaultCipher;
use sigyn_core::error::Result;
pub use sigyn_core::policy::storage::VaultPolicy;
use uuid::Uuid;

/// Extension trait adding filesystem I/O to VaultPolicy.
pub trait VaultPolicyExt: Sized {
    fn save_signed(
        &self,
        path: &Path,
        cipher: &VaultCipher,
        signing_key: &SigningKeyPair,
        vault_id: &Uuid,
    ) -> Result<()>;
    fn load_signed(
        path: &Path,
        cipher: &VaultCipher,
        verifying_key: &VerifyingKeyWrapper,
        vault_id: &Uuid,
    ) -> Result<Self>;
    /// Load an encrypted policy without signature verification (migration fallback).
    fn load_encrypted(path: &Path, cipher: &VaultCipher) -> Result<Self>;
}

impl VaultPolicyExt for VaultPolicy {
    fn save_signed(
        &self,
        path: &Path,
        cipher: &VaultCipher,
        signing_key: &SigningKeyPair,
        vault_id: &Uuid,
    ) -> Result<()> {
        let bytes = self.to_signed_encrypted_bytes(cipher, signing_key, vault_id)?;
        crate::io::atomic_write(path, &bytes)
    }

    fn load_signed(
        path: &Path,
        cipher: &VaultCipher,
        verifying_key: &VerifyingKeyWrapper,
        vault_id: &Uuid,
    ) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read(path)?;
        Self::from_signed_encrypted_bytes(&data, cipher, verifying_key, vault_id)
    }

    fn load_encrypted(path: &Path, cipher: &VaultCipher) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read(path)?;
        Self::from_encrypted_bytes(&data, cipher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::crypto::keys::{KeyFingerprint, SigningKeyPair};
    use sigyn_core::crypto::vault_cipher::VaultCipher;
    use sigyn_core::policy::member::MemberPolicy;
    use sigyn_core::policy::roles::Role;

    fn test_fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    #[test]
    fn test_save_load_signed_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy-signed.cbor");
        let cipher = VaultCipher::generate();
        let kp = SigningKeyPair::generate();
        let vk = kp.verifying_key();
        let vault_id = Uuid::new_v4();

        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(test_fp(0xAA), Role::Admin));

        policy.save_signed(&path, &cipher, &kp, &vault_id).unwrap();
        let loaded = VaultPolicy::load_signed(&path, &cipher, &vk, &vault_id).unwrap();

        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.get_member(&test_fp(0xAA)).unwrap().role, Role::Admin);
    }

    #[test]
    fn test_load_signed_rejects_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy-unsigned.cbor");
        let cipher = VaultCipher::generate();
        let kp = SigningKeyPair::generate();
        let vk = kp.verifying_key();
        let vault_id = Uuid::new_v4();

        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(test_fp(0xBB), Role::Contributor));

        // Write unsigned bytes directly
        let unsigned_bytes = policy.to_encrypted_bytes(&cipher).unwrap();
        crate::io::atomic_write(&path, &unsigned_bytes).unwrap();
        // Load with signed loader — should reject unsigned
        assert!(VaultPolicy::load_signed(&path, &cipher, &vk, &vault_id).is_err());
    }

    #[test]
    fn test_load_signed_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.cbor");
        let cipher = VaultCipher::generate();
        let kp = SigningKeyPair::generate();
        let vk = kp.verifying_key();
        let vault_id = Uuid::new_v4();

        let loaded = VaultPolicy::load_signed(&path, &cipher, &vk, &vault_id).unwrap();
        assert!(loaded.members.is_empty());
    }
}
