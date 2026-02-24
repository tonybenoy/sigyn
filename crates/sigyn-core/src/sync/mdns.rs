use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanPeer {
    pub name: String,
    pub addr: String,
    pub vault_names: Vec<String>,
    pub fingerprint: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Default)]
pub struct PeerRegistry {
    peers: HashMap<String, LanPeer>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_peer(&mut self, peer: LanPeer) {
        self.peers.insert(peer.fingerprint.clone(), peer);
    }

    pub fn remove_peer(&mut self, fingerprint: &str) {
        self.peers.remove(fingerprint);
    }

    pub fn list_peers(&self) -> Vec<&LanPeer> {
        self.peers.values().collect()
    }

    pub fn find_peers_for_vault(&self, vault_name: &str) -> Vec<&LanPeer> {
        self.peers
            .values()
            .filter(|p| p.vault_names.iter().any(|v| v == vault_name))
            .collect()
    }

    pub fn prune_stale(&mut self, max_age: chrono::Duration) {
        let cutoff = chrono::Utc::now() - max_age;
        self.peers.retain(|_, p| p.last_seen > cutoff);
    }
}

// ---------------------------------------------------------------------------
// File-based LAN peer advertisement / discovery
// ---------------------------------------------------------------------------

/// Information about a discovered peer, read from a `.peer.json` file in a
/// shared directory (e.g. a mounted network volume or NFS share).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub fingerprint: String,
    pub hostname: String,
    pub vault_name: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Optional Ed25519 signature over the peer info (hex-encoded).
    /// Unsigned peers are still discovered but flagged with a warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Advertise this peer by writing a JSON file into `shared_dir`.
///
/// The file is named `<fingerprint_hex>.peer.json` so that each peer
/// overwrites only its own advertisement on repeated calls.
pub fn advertise_peer(
    shared_dir: &Path,
    vault_name: &str,
    fingerprint: &KeyFingerprint,
    hostname: &str,
) -> Result<()> {
    std::fs::create_dir_all(shared_dir)?;

    let info = PeerInfo {
        fingerprint: fingerprint.to_hex(),
        hostname: hostname.to_string(),
        vault_name: vault_name.to_string(),
        last_seen: chrono::Utc::now(),
        signature: None, // TODO: sign with identity signing key when available
    };

    let filename = format!("{}.peer.json", fingerprint.to_hex());
    let path = shared_dir.join(filename);
    let json = serde_json::to_string_pretty(&info)
        .map_err(|e| crate::error::SigynError::Serialization(e.to_string()))?;
    std::fs::write(&path, json)?;

    Ok(())
}

/// Discover peers by scanning `shared_dir` for `.peer.json` files.
///
/// Only peers advertising the given `vault_name` are returned.
/// Stale entries (last_seen older than 5 minutes) are pruned automatically:
/// they are deleted from disk and omitted from the result.
pub fn discover_peers(shared_dir: &Path, vault_name: &str) -> Result<Vec<PeerInfo>> {
    let mut peers = Vec::new();

    if !shared_dir.exists() {
        return Ok(peers);
    }

    let cutoff = chrono::Utc::now() - chrono::Duration::minutes(5);

    for entry in std::fs::read_dir(shared_dir)? {
        let entry = entry?;
        let path = entry.path();

        let is_peer_file = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".peer.json"))
            .unwrap_or(false);

        if !is_peer_file {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let info: PeerInfo = match serde_json::from_str(&contents) {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Prune stale entries
        if info.last_seen < cutoff {
            if let Err(e) = std::fs::remove_file(&path) {
                eprintln!(
                    "warning: failed to remove stale peer file {:?}: {}",
                    path, e
                );
            }
            continue;
        }

        if info.vault_name == vault_name {
            if info.signature.is_none() {
                eprintln!(
                    "warning: discovered unsigned peer {} ({})",
                    info.fingerprint, info.hostname
                );
            }
            peers.push(info);
        }
    }

    Ok(peers)
}
