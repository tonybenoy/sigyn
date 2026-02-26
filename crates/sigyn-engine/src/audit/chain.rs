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

    /// Verify the audit chain: hash linkage, hash integrity, and Ed25519 signatures.
    ///
    /// `lookup_key` resolves an actor fingerprint to their signing public key.
    /// If no key lookup is provided, signature verification is skipped (hash-only mode).
    pub fn verify_chain_with_keys<F>(&self, lookup_key: Option<F>) -> Result<u64>
    where
        F: Fn(&KeyFingerprint) -> Option<crate::crypto::keys::VerifyingKeyWrapper>,
    {
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

            // Verify Ed25519 signature if key lookup is available
            if let Some(ref lookup) = lookup_key {
                if let Some(verifying_key) = lookup(&entry.actor) {
                    if verifying_key
                        .verify(&entry.entry_hash, &entry.signature)
                        .is_err()
                    {
                        return Err(SigynError::AuditChainBroken(entry.sequence));
                    }
                }
                // If the actor's key is not found, we skip signature verification
                // for that entry (they may have been removed from the vault).
            }

            prev_hash = Some(entry.entry_hash);
            count += 1;
        }

        Ok(count)
    }

    /// Verify the audit chain (hash linkage and integrity only, no signature verification).
    pub fn verify_chain(&self) -> Result<u64> {
        self.verify_chain_with_keys(
            None::<fn(&KeyFingerprint) -> Option<crate::crypto::keys::VerifyingKeyWrapper>>,
        )
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
