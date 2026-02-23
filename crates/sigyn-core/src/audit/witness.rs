use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use crate::crypto::keys::{KeyFingerprint, VerifyingKeyWrapper};
use crate::error::{SigynError, Result};

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

/// Persistent storage for witness records, stored as a JSON file alongside the audit log.
pub struct WitnessLog {
    path: PathBuf,
    entries: Vec<WitnessedEntry>,
}

impl WitnessLog {
    /// Open (or create) a witness log at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let entries = if path.exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str(&data)
                .map_err(|e| SigynError::Deserialization(e.to_string()))?
        } else {
            Vec::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Add a witness signature for the given entry hash. If no WitnessedEntry exists
    /// for that hash yet, one is created with `required_witnesses = 1`.
    pub fn add_witness(
        &mut self,
        entry_hash: [u8; 32],
        witness: WitnessSignature,
    ) -> Result<()> {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.entry_hash == entry_hash) {
            existing.signatures.push(witness);
        } else {
            self.entries.push(WitnessedEntry {
                entry_hash,
                signatures: vec![witness],
                required_witnesses: 1,
            });
        }
        self.save()
    }

    /// Return all witness signatures recorded for a particular entry hash.
    pub fn witnesses_for(&self, entry_hash: &[u8; 32]) -> Vec<&WitnessSignature> {
        self.entries
            .iter()
            .filter(|e| &e.entry_hash == entry_hash)
            .flat_map(|e| e.signatures.iter())
            .collect()
    }

    /// Return all witnessed entries.
    pub fn entries(&self) -> &[WitnessedEntry] {
        &self.entries
    }

    /// Persist the witness log to disk.
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| SigynError::Serialization(e.to_string()))?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}
