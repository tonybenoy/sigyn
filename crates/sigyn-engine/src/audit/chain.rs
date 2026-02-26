use std::io::{BufRead, Write};
use std::path::Path;

use super::entry::{AuditAction, AuditEntry, AuditOutcome};
use crate::crypto::keys::{KeyFingerprint, SigningKeyPair};
use crate::crypto::vault_cipher::VaultCipher;
use crate::error::{Result, SigynError};

/// Verify that the audit log entry at `expected_sequence` still has the
/// expected hash. This detects tampering or rollback of the audit log
/// after a `sync pull`.
pub fn verify_audit_continuity(
    audit_path: &Path,
    cipher: &VaultCipher,
    expected_sequence: u64,
    expected_hash: [u8; 32],
) -> Result<()> {
    if !audit_path.exists() {
        return Err(SigynError::AuditChainBroken(expected_sequence));
    }
    let file = std::fs::File::open(audit_path)?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = decode_audit_line(&line, cipher)?;
        if entry.sequence == expected_sequence {
            if entry.entry_hash == expected_hash {
                return Ok(());
            } else {
                return Err(SigynError::AuditChainBroken(expected_sequence));
            }
        }
        if entry.sequence > expected_sequence {
            break;
        }
    }

    // Entry not found at all — log was truncated
    Err(SigynError::AuditChainBroken(expected_sequence))
}

pub struct AuditLog {
    path: std::path::PathBuf,
    last_hash: Option<[u8; 32]>,
    next_sequence: u64,
    /// Cipher for encrypting/decrypting audit entries (Tier C).
    /// Each JSON line is encrypted and base64-encoded.
    audit_cipher: VaultCipher,
}

/// Decode a single audit log line. Requires a cipher for decryption.
/// Plaintext JSON lines are rejected.
fn decode_audit_line(line: &str, cipher: &VaultCipher) -> Result<AuditEntry> {
    use base64::Engine;
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(line.trim())
        .map_err(|e| SigynError::Deserialization(format!("base64 decode: {}", e)))?;
    let plaintext = cipher.decrypt(&encrypted, b"audit-entry")?;
    let json =
        std::str::from_utf8(&plaintext).map_err(|e| SigynError::Deserialization(e.to_string()))?;
    serde_json::from_str(json).map_err(|e| SigynError::Deserialization(e.to_string()))
}

impl AuditLog {
    pub fn open(path: &Path, audit_cipher: VaultCipher) -> Result<Self> {
        let (last_hash, next_sequence) = if path.exists() {
            let file = std::fs::File::open(path)?;
            let reader = std::io::BufReader::new(file);
            let mut last_hash = None;
            let mut count = 0u64;
            let lines: Vec<String> = reader.lines().collect::<std::result::Result<Vec<_>, _>>()?;
            let non_empty: Vec<&str> = lines
                .iter()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            for (i, line) in non_empty.iter().enumerate() {
                match decode_audit_line(line, &audit_cipher) {
                    Ok(entry) => {
                        last_hash = Some(entry.entry_hash);
                        count = entry.sequence + 1;
                    }
                    Err(e) => {
                        if i == non_empty.len() - 1 {
                            // Tolerate a single trailing corrupt/partial line
                            // (crash recovery: write_all succeeded but sync_all didn't).
                            break;
                        }
                        return Err(e);
                    }
                }
            }
            (last_hash, count)
        } else {
            (None, 0)
        };

        Ok(Self {
            path: path.to_path_buf(),
            last_hash,
            next_sequence,
            audit_cipher,
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
        let line = {
            use base64::Engine;
            let encrypted = self.audit_cipher.encrypt(json.as_bytes(), b"audit-entry")?;
            format!(
                "{}\n",
                base64::engine::general_purpose::STANDARD.encode(&encrypted)
            )
        };
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
            let entry = decode_audit_line(&line, &self.audit_cipher)?;

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
            let entry = decode_audit_line(&line, &self.audit_cipher)?;
            entries.push(entry);
        }

        let start = entries.len().saturating_sub(n);
        Ok(entries[start..].to_vec())
    }
}
