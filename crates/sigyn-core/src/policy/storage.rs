use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::constraints::Constraints;
use super::member::MemberPolicy;
use crate::crypto::keys::KeyFingerprint;
use crate::error::{Result, SigynError};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultPolicy {
    pub members: IndexMap<String, MemberPolicy>,
    pub global_constraints: Option<Constraints>,
}

impl VaultPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a member policy. Callers must enforce RBAC checks before calling this.
    pub fn add_member(&mut self, policy: MemberPolicy) {
        self.members.insert(policy.fingerprint.to_hex(), policy);
    }

    /// Remove a member by fingerprint. Callers must enforce RBAC checks before calling this.
    pub fn remove_member(&mut self, fingerprint: &KeyFingerprint) -> Option<MemberPolicy> {
        self.members.shift_remove(&fingerprint.to_hex())
    }

    pub fn get_member(&self, fingerprint: &KeyFingerprint) -> Option<&MemberPolicy> {
        self.members.get(&fingerprint.to_hex())
    }

    pub fn get_member_mut(&mut self, fingerprint: &KeyFingerprint) -> Option<&mut MemberPolicy> {
        self.members.get_mut(&fingerprint.to_hex())
    }

    pub fn members(&self) -> impl Iterator<Item = &MemberPolicy> {
        self.members.values()
    }

    pub fn save_encrypted(&self, path: &Path, cipher: &crate::crypto::VaultCipher) -> Result<()> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| SigynError::CborEncode(e.to_string()))?;
        let encrypted = cipher.encrypt(&buf, b"policy")?;
        atomic_write(path, &encrypted)
    }

    pub fn load_encrypted(path: &Path, cipher: &crate::crypto::VaultCipher) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read(path)?;
        let decrypted = cipher.decrypt(&data, b"policy")?;
        ciborium::from_reader(decrypted.as_slice())
            .map_err(|e| SigynError::CborDecode(e.to_string()))
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    let file = tmp.persist(path).map_err(|e| SigynError::Io(e.error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyFingerprint;
    use crate::crypto::vault_cipher::VaultCipher;
    use crate::policy::member::MemberPolicy;
    use crate::policy::roles::Role;

    fn test_fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    #[test]
    fn test_new_policy_is_empty() {
        let policy = VaultPolicy::new();
        assert!(policy.members.is_empty());
        assert!(policy.global_constraints.is_none());
    }

    #[test]
    fn test_add_and_get_member() {
        let mut policy = VaultPolicy::new();
        let fp = test_fp(0xAA);
        let member = MemberPolicy::new(fp.clone(), Role::Contributor);
        policy.add_member(member);

        let retrieved = policy.get_member(&fp);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().role, Role::Contributor);
    }

    #[test]
    fn test_remove_member() {
        let mut policy = VaultPolicy::new();
        let fp = test_fp(0xBB);
        policy.add_member(MemberPolicy::new(fp.clone(), Role::Admin));

        let removed = policy.remove_member(&fp);
        assert!(removed.is_some());
        assert!(policy.get_member(&fp).is_none());
    }

    #[test]
    fn test_remove_nonexistent_member() {
        let mut policy = VaultPolicy::new();
        let fp = test_fp(0xCC);
        assert!(policy.remove_member(&fp).is_none());
    }

    #[test]
    fn test_get_member_mut() {
        let mut policy = VaultPolicy::new();
        let fp = test_fp(0xDD);
        policy.add_member(MemberPolicy::new(fp.clone(), Role::Contributor));

        let member = policy.get_member_mut(&fp).unwrap();
        member.role = Role::Admin;

        assert_eq!(policy.get_member(&fp).unwrap().role, Role::Admin);
    }

    #[test]
    fn test_members_iterator() {
        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(test_fp(1), Role::ReadOnly));
        policy.add_member(MemberPolicy::new(test_fp(2), Role::Admin));
        policy.add_member(MemberPolicy::new(test_fp(3), Role::Owner));

        let members: Vec<_> = policy.members().collect();
        assert_eq!(members.len(), 3);
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
