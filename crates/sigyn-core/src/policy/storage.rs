use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

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

    /// Encrypt the policy to bytes using the given cipher.
    pub fn to_encrypted_bytes(&self, cipher: &crate::crypto::VaultCipher) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| SigynError::CborEncode(e.to_string()))?;
        cipher.encrypt(&buf, b"policy")
    }

    /// Decrypt a policy from bytes using the given cipher.
    pub fn from_encrypted_bytes(data: &[u8], cipher: &crate::crypto::VaultCipher) -> Result<Self> {
        let decrypted = cipher.decrypt(data, b"policy")?;
        ciborium::from_reader(decrypted.as_slice())
            .map_err(|e| SigynError::CborDecode(e.to_string()))
    }
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
    fn test_encrypted_roundtrip() {
        let cipher = VaultCipher::generate();

        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(test_fp(0xEE), Role::Manager));

        let bytes = policy.to_encrypted_bytes(&cipher).unwrap();
        let loaded = VaultPolicy::from_encrypted_bytes(&bytes, &cipher).unwrap();

        assert_eq!(loaded.members.len(), 1);
        let fp = test_fp(0xEE);
        assert_eq!(loaded.get_member(&fp).unwrap().role, Role::Manager);
    }
}
