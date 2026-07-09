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
        self.upsert_signature(WitnessSignature {
            witness,
            signature,
            timestamp: chrono::Utc::now(),
        });
    }

    /// Insert a witness signature, replacing any existing signature from the
    /// same witness fingerprint. A witness signing repeatedly must never
    /// accumulate multiple quorum slots.
    pub fn upsert_signature(&mut self, sig: WitnessSignature) {
        if let Some(existing) = self
            .signatures
            .iter_mut()
            .find(|s| s.witness == sig.witness)
        {
            *existing = sig;
        } else {
            self.signatures.push(sig);
        }
    }

    /// Number of *distinct* witnesses (deduplicated by fingerprint).
    /// Signature lists loaded from disk may contain duplicates (legacy files
    /// or a malicious writer), so quorum must never count raw length.
    pub fn unique_witness_count(&self) -> u32 {
        let mut seen: Vec<&KeyFingerprint> = Vec::new();
        for ws in &self.signatures {
            if !seen.contains(&&ws.witness) {
                seen.push(&ws.witness);
            }
        }
        seen.len() as u32
    }

    pub fn is_fully_witnessed(&self) -> bool {
        self.unique_witness_count() >= self.required_witnesses
    }

    /// Verify witness signatures and return the number of *distinct* witnesses
    /// whose signature verified. Duplicate signatures from the same fingerprint
    /// count once. An invalid signature is an error.
    pub fn verify_witnesses(
        &self,
        verifying_keys: &[(KeyFingerprint, VerifyingKeyWrapper)],
    ) -> Result<u32> {
        let mut verified: Vec<&KeyFingerprint> = Vec::new();
        for ws in &self.signatures {
            if verified.contains(&&ws.witness) {
                continue;
            }
            if let Some((_, vk)) = verifying_keys.iter().find(|(fp, _)| fp == &ws.witness) {
                vk.verify(&self.entry_hash, &ws.signature)?;
                verified.push(&ws.witness);
            }
        }
        Ok(verified.len() as u32)
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

    #[test]
    fn test_same_witness_signing_repeatedly_does_not_satisfy_quorum() {
        let entry_hash = [0xAAu8; 32];
        let mut entry = WitnessedEntry::new(entry_hash, 3);

        let kp = SigningKeyPair::generate();
        let fp = KeyFingerprint([1u8; 16]);

        // One witness signs three times via the API — must collapse to one slot.
        entry.add_witness(fp.clone(), &kp);
        entry.add_witness(fp.clone(), &kp);
        entry.add_witness(fp.clone(), &kp);
        assert_eq!(entry.signatures.len(), 1);
        assert!(
            !entry.is_fully_witnessed(),
            "one witness must not satisfy a 3-of-M quorum"
        );

        // Even raw duplicate records (e.g. from a tampered/legacy file) must
        // not inflate the quorum count.
        let sig = kp.sign(&entry_hash);
        entry.signatures.push(WitnessSignature {
            witness: fp.clone(),
            signature: sig.clone(),
            timestamp: chrono::Utc::now(),
        });
        entry.signatures.push(WitnessSignature {
            witness: fp.clone(),
            signature: sig,
            timestamp: chrono::Utc::now(),
        });
        assert_eq!(entry.signatures.len(), 3);
        assert_eq!(entry.unique_witness_count(), 1);
        assert!(!entry.is_fully_witnessed());

        // verify_witnesses must also count distinct witnesses only.
        let vks = vec![(fp, kp.verifying_key())];
        assert_eq!(entry.verify_witnesses(&vks).unwrap(), 1);

        // Two more distinct witnesses complete the quorum.
        let kp2 = SigningKeyPair::generate();
        let kp3 = SigningKeyPair::generate();
        entry.add_witness(KeyFingerprint([2u8; 16]), &kp2);
        entry.add_witness(KeyFingerprint([3u8; 16]), &kp3);
        assert!(entry.is_fully_witnessed());
    }
}
