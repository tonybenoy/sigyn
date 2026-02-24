use std::path::Path;

use sigyn_core::crypto::VaultCipher;
use sigyn_core::error::Result;
pub use sigyn_core::policy::storage::VaultPolicy;

/// Extension trait adding filesystem I/O to VaultPolicy.
pub trait VaultPolicyExt: Sized {
    fn save_encrypted(&self, path: &Path, cipher: &VaultCipher) -> Result<()>;
    fn load_encrypted(path: &Path, cipher: &VaultCipher) -> Result<Self>;
}

impl VaultPolicyExt for VaultPolicy {
    fn save_encrypted(&self, path: &Path, cipher: &VaultCipher) -> Result<()> {
        let bytes = self.to_encrypted_bytes(cipher)?;
        crate::io::atomic_write(path, &bytes)
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
    use sigyn_core::crypto::keys::KeyFingerprint;
    use sigyn_core::crypto::vault_cipher::VaultCipher;
    use sigyn_core::policy::member::MemberPolicy;
    use sigyn_core::policy::roles::Role;

    fn test_fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    #[test]
    fn test_save_load_encrypted_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.cbor");
        let cipher = VaultCipher::generate();

        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(test_fp(0xEE), Role::Manager));

        policy.save_encrypted(&path, &cipher).unwrap();
        let loaded = VaultPolicy::load_encrypted(&path, &cipher).unwrap();

        assert_eq!(loaded.members.len(), 1);
        let fp = test_fp(0xEE);
        assert_eq!(loaded.get_member(&fp).unwrap().role, Role::Manager);
    }

    #[test]
    fn test_load_encrypted_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.cbor");
        let cipher = VaultCipher::generate();

        let loaded = VaultPolicy::load_encrypted(&path, &cipher).unwrap();
        assert!(loaded.members.is_empty());
    }
}
