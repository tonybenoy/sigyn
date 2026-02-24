use std::path::{Path, PathBuf};

use sigyn_core::audit::witness::{WitnessSignature, WitnessedEntry};
use sigyn_core::error::{Result, SigynError};

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
            serde_json::from_str(&data).map_err(|e| SigynError::Deserialization(e.to_string()))?
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
    pub fn add_witness(&mut self, entry_hash: [u8; 32], witness: WitnessSignature) -> Result<()> {
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

    /// Persist the witness log to disk atomically.
    fn save(&self) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| SigynError::Serialization(e.to_string()))?;
        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(json.as_bytes())?;
        tmp.persist(&self.path)
            .map_err(|e| SigynError::Io(e.error))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::crypto::keys::KeyFingerprint;
    use tempfile::tempdir;

    #[test]
    fn test_witness_log_persistence() {
        let tmp = tempdir().unwrap();
        let log_path = tmp.path().join("witness.json");
        let entry_hash = [0xBBu8; 32];
        let witness_fp = KeyFingerprint([3u8; 16]);

        {
            let mut log = WitnessLog::open(&log_path).unwrap();
            let sig = WitnessSignature {
                witness: witness_fp.clone(),
                signature: vec![0u8; 64],
                timestamp: chrono::Utc::now(),
            };
            log.add_witness(entry_hash, sig).unwrap();
        }

        // Reopen and check
        {
            let log = WitnessLog::open(&log_path).unwrap();
            let witnesses = log.witnesses_for(&entry_hash);
            assert_eq!(witnesses.len(), 1);
            assert_eq!(witnesses[0].witness, witness_fp);
        }
    }
}
