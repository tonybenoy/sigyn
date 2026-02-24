use crate::crypto::keys::{KeyFingerprint, VerifyingKeyWrapper};
use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness: KeyFingerprint,
    pub signature: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessedEntry {
    pub entry_hash: [u8; 32],
    pub signatures: Vec<WitnessSignature>,
    pub required_witnesses: u32,
}

impl WitnessedEntry {
    pub fn new(entry_hash: [u8; 32], required_witnesses: u32) -> Self {
        Self {
            entry_hash,
            signatures: Vec::new(),
            required_witnesses,
        }
    }

    pub fn add_witness(
        &mut self,
        witness: KeyFingerprint,
        signing_key: &crate::crypto::SigningKeyPair,
    ) {
        let signature = signing_key.sign(&self.entry_hash);
        self.signatures.push(WitnessSignature {
            witness,
            signature,
            timestamp: chrono::Utc::now(),
        });
    }

    pub fn is_fully_witnessed(&self) -> bool {
        self.signatures.len() as u32 >= self.required_witnesses
    }

    pub fn verify_witnesses(
        &self,
        verifying_keys: &[(KeyFingerprint, VerifyingKeyWrapper)],
    ) -> Result<u32> {
        let mut verified = 0u32;
        for ws in &self.signatures {
            if let Some((_, vk)) = verifying_keys.iter().find(|(fp, _)| fp == &ws.witness) {
                vk.verify(&self.entry_hash, &ws.signature)?;
                verified += 1;
            }
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKeyPair;

    #[test]
    fn test_witness_entry_logic() {
        let entry_hash = [0xAAu8; 32];
        let mut entry = WitnessedEntry::new(entry_hash, 2);
        assert!(!entry.is_fully_witnessed());

        let witness1_kp = SigningKeyPair::generate();
        let witness1_fp = KeyFingerprint([1u8; 16]);
        let witness2_kp = SigningKeyPair::generate();
        let witness2_fp = KeyFingerprint([2u8; 16]);

        entry.add_witness(witness1_fp.clone(), &witness1_kp);
        assert!(!entry.is_fully_witnessed());
        assert_eq!(entry.signatures.len(), 1);

        entry.add_witness(witness2_fp.clone(), &witness2_kp);
        assert!(entry.is_fully_witnessed());

        // Verify witnesses
        let vks = vec![
            (witness1_fp, witness1_kp.verifying_key()),
            (witness2_fp, witness2_kp.verifying_key()),
        ];
        let verified_count = entry.verify_witnesses(&vks).unwrap();
        assert_eq!(verified_count, 2);
    }
}
