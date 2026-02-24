use std::io::{BufRead, Write};
use std::path::Path;

use super::entry::{AuditAction, AuditEntry, AuditOutcome};
use crate::crypto::keys::{KeyFingerprint, SigningKeyPair};
use crate::error::{Result, SigynError};

pub struct AuditLog {
    path: std::path::PathBuf,
    last_hash: Option<[u8; 32]>,
    next_sequence: u64,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        let (last_hash, next_sequence) = if path.exists() {
            let file = std::fs::File::open(path)?;
            let reader = std::io::BufReader::new(file);
            let mut last_hash = None;
            let mut count = 0u64;
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: AuditEntry = serde_json::from_str(&line)
                    .map_err(|e| SigynError::Deserialization(e.to_string()))?;
                last_hash = Some(entry.entry_hash);
                count = entry.sequence + 1;
            }
            (last_hash, count)
        } else {
            (None, 0)
        };

        Ok(Self {
            path: path.to_path_buf(),
            last_hash,
            next_sequence,
        })
    }

    pub fn append(
        &mut self,
        actor: &KeyFingerprint,
        action: AuditAction,
        env: Option<String>,
        outcome: AuditOutcome,
        signing_key: &SigningKeyPair,
    ) -> Result<AuditEntry> {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        let mut entry = AuditEntry {
            sequence: self.next_sequence,
            timestamp: chrono::Utc::now(),
            actor: actor.clone(),
            action,
            env,
            outcome,
            nonce,
            prev_hash: self.last_hash,
            entry_hash: [0u8; 32],
            signature: Vec::new(),
        };

        let hash_input = serde_json::to_vec(&(
            &entry.sequence,
            &entry.timestamp,
            &entry.actor,
            &entry.action,
            &entry.env,
            &entry.outcome,
            &entry.nonce,
            &entry.prev_hash,
        ))
        .map_err(|e| SigynError::Serialization(e.to_string()))?;
        entry.entry_hash = *blake3::hash(&hash_input).as_bytes();

        entry.signature = signing_key.sign(&entry.entry_hash);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write to a temp file first, then append atomically to avoid partial writes
        let json =
            serde_json::to_string(&entry).map_err(|e| SigynError::Serialization(e.to_string()))?;
        let line = format!("{}\n", json);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;

        self.last_hash = Some(entry.entry_hash);
        self.next_sequence += 1;

        Ok(entry)
    }

    pub fn verify_chain(&self) -> Result<u64> {
        if !self.path.exists() {
            return Ok(0);
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        let mut prev_hash: Option<[u8; 32]> = None;
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| SigynError::Deserialization(e.to_string()))?;

            if entry.prev_hash != prev_hash {
                return Err(SigynError::AuditChainBroken(entry.sequence));
            }

            // Recompute hash to verify integrity
            let hash_input = serde_json::to_vec(&(
                &entry.sequence,
                &entry.timestamp,
                &entry.actor,
                &entry.action,
                &entry.env,
                &entry.outcome,
                &entry.nonce,
                &entry.prev_hash,
            ))
            .map_err(|e| SigynError::Serialization(e.to_string()))?;
            let computed_hash = *blake3::hash(&hash_input).as_bytes();
            if computed_hash != entry.entry_hash {
                return Err(SigynError::AuditChainBroken(entry.sequence));
            }

            prev_hash = Some(entry.entry_hash);
            count += 1;
        }

        Ok(count)
    }

    pub fn tail(&self, n: usize) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| SigynError::Deserialization(e.to_string()))?;
            entries.push(entry);
        }

        let start = entries.len().saturating_sub(n);
        Ok(entries[start..].to_vec())
    }
}
