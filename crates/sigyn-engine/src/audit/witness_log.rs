use std::path::{Path, PathBuf};

use sigyn_core::audit::witness::{WitnessSignature, WitnessedEntry};
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::error::{Result, SigynError};

/// AAD for witness log encryption.
const WITNESS_AAD: &[u8] = b"witness-log";

/// Persistent storage for witness records, encrypted with a vault-derived cipher.
pub struct WitnessLog {
    path: PathBuf,
    cipher: VaultCipher,
    entries: Vec<WitnessedEntry>,
}

impl WitnessLog {
    /// Open (or create) a witness log at the given path, encrypted with the given cipher.
    pub fn open(path: &Path, cipher: VaultCipher) -> Result<Self> {
        let entries = if path.exists() {
            let data = std::fs::read(path)?;
            let plaintext = cipher.decrypt(&data, WITNESS_AAD)?;
            let json = std::str::from_utf8(&plaintext)
                .map_err(|e| SigynError::Deserialization(e.to_string()))?;
            serde_json::from_str(json).map_err(|e| SigynError::Deserialization(e.to_string()))?
        } else {
            Vec::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            cipher,
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

    /// Persist the witness log to disk atomically (encrypted).
    fn save(&self) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| SigynError::Serialization(e.to_string()))?;
        let encrypted = self.cipher.encrypt(json.as_bytes(), WITNESS_AAD)?;
        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(&encrypted)?;
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

    const TEST_KEY: [u8; 32] = [0x42u8; 32];

    fn make_cipher() -> VaultCipher {
        VaultCipher::new(TEST_KEY)
    }

    #[test]
    fn test_witness_log_persistence() {
        let tmp = tempdir().unwrap();
        let log_path = tmp.path().join("witness.json");
        let entry_hash = [0xBBu8; 32];
        let witness_fp = KeyFingerprint([3u8; 16]);

        {
            let mut log = WitnessLog::open(&log_path, make_cipher()).unwrap();
            let sig = WitnessSignature {
                witness: witness_fp.clone(),
                signature: vec![0u8; 64],
                timestamp: chrono::Utc::now(),
            };
            log.add_witness(entry_hash, sig).unwrap();
        }

        // Reopen and check
        {
            let log = WitnessLog::open(&log_path, make_cipher()).unwrap();
            let witnesses = log.witnesses_for(&entry_hash);
            assert_eq!(witnesses.len(), 1);
            assert_eq!(witnesses[0].witness, witness_fp);
        }
    }

    #[test]
    fn test_witness_log_tamper_rejected() {
        let tmp = tempdir().unwrap();
        let log_path = tmp.path().join("witness.json");
        let entry_hash = [0xCCu8; 32];

        {
            let mut log = WitnessLog::open(&log_path, make_cipher()).unwrap();
            let sig = WitnessSignature {
                witness: KeyFingerprint([1u8; 16]),
                signature: vec![0u8; 64],
                timestamp: chrono::Utc::now(),
            };
            log.add_witness(entry_hash, sig).unwrap();
        }

        // Tamper with the encrypted file
        let mut data = std::fs::read(&log_path).unwrap();
        if data.len() > 10 {
            data[10] ^= 0xFF;
        }
        std::fs::write(&log_path, &data).unwrap();

        // Opening should fail
        let result = WitnessLog::open(&log_path, make_cipher());
        assert!(result.is_err(), "tampered witness log should fail to open");
    }

    #[test]
    fn test_witness_log_wrong_key_rejected() {
        let tmp = tempdir().unwrap();
        let log_path = tmp.path().join("witness.json");
        let entry_hash = [0xDDu8; 32];

        {
            let mut log = WitnessLog::open(&log_path, make_cipher()).unwrap();
            let sig = WitnessSignature {
                witness: KeyFingerprint([2u8; 16]),
                signature: vec![0u8; 64],
                timestamp: chrono::Utc::now(),
            };
            log.add_witness(entry_hash, sig).unwrap();
        }

        // Try to open with a different key
        let wrong_cipher = VaultCipher::new([0x99u8; 32]);
        let result = WitnessLog::open(&log_path, wrong_cipher);
        assert!(
            result.is_err(),
            "wrong key should fail to decrypt witness log"
        );
    }
}
