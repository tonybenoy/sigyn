use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::keys::KeyFingerprint;

/// TOFU pin: records the owner identity observed on first vault access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPin {
    pub vault_id: Uuid,
    pub owner_fingerprint: KeyFingerprint,
    /// Raw Ed25519 verifying key bytes of the owner at pin time.
    pub owner_signing_pubkey_bytes: Vec<u8>,
    pub pinned_at: DateTime<Utc>,
}

/// Last-known-good commit OIDs and audit chain tip, updated after every
/// successful pull/push. Used for rollback detection on the next pull.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultSyncCheckpoint {
    /// Git OID of the vault repo HEAD after last successful sync.
    pub vault_commit_oid: Option<String>,
    /// Git OID of the audit repo HEAD (only set for split-repo layouts).
    pub audit_commit_oid: Option<String>,
    /// Sequence number of the last audit entry we verified.
    pub audit_sequence: Option<u64>,
    /// blake3 hash of the last audit entry we verified.
    pub audit_tip_hash: Option<[u8; 32]>,
}

/// Per-vault local state that is **never synced** — device-only.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalVaultState {
    pub pin: Option<VaultPin>,
    pub checkpoint: Option<VaultSyncCheckpoint>,
}

/// Device-key-encrypted store of per-vault local state.
/// Persisted at `~/.sigyn/pinned_vaults.cbor`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PinnedVaultsStore {
    /// Keyed by vault name (same as the directory name under `vaults/`).
    pub vaults: HashMap<String, LocalVaultState>,
}

impl PinnedVaultsStore {
    pub fn new() -> Self {
        Self {
            vaults: HashMap::new(),
        }
    }

    /// Get or create the local state entry for a vault.
    pub fn entry_mut(&mut self, vault_name: &str) -> &mut LocalVaultState {
        self.vaults.entry(vault_name.to_string()).or_default()
    }

    /// Get the local state for a vault, if it exists.
    pub fn get(&self, vault_name: &str) -> Option<&LocalVaultState> {
        self.vaults.get(vault_name)
    }

    /// Remove a vault entry from the store. Returns the removed state if it existed.
    pub fn remove(&mut self, vault_name: &str) -> Option<LocalVaultState> {
        self.vaults.remove(vault_name)
    }
}
