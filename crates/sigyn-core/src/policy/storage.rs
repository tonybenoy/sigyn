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

    pub fn add_member(&mut self, policy: MemberPolicy) {
        self.members.insert(policy.fingerprint.to_hex(), policy);
    }

    pub fn remove_member(&mut self, fingerprint: &KeyFingerprint) -> Option<MemberPolicy> {
        self.members.shift_remove(&fingerprint.to_hex())
    }

    pub fn get_member(&self, fingerprint: &KeyFingerprint) -> Option<&MemberPolicy> {
        self.members.get(&fingerprint.to_hex())
    }

    pub fn get_member_mut(&mut self, fingerprint: &KeyFingerprint) -> Option<&mut MemberPolicy> {
        self.members.get_mut(&fingerprint.to_hex())
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
    tmp.persist(path).map_err(|e| SigynError::Io(e.error))?;
    Ok(())
}
