use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;
use crate::error::Result;

/// Default MFA session grace period: 1 hour.
pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSession {
    pub verified_at: DateTime<Utc>,
    /// HMAC of verified_at using fingerprint bytes as key, for tamper detection.
    pub hmac: String,
}

pub struct MfaSessionStore {
    session_dir: PathBuf,
}

impl MfaSessionStore {
    pub fn new(session_dir: PathBuf) -> Self {
        Self { session_dir }
    }

    fn session_path(&self, fingerprint: &KeyFingerprint) -> PathBuf {
        self.session_dir
            .join(format!("{}.session", fingerprint.to_hex()))
    }

    /// Check if a valid MFA session exists within the grace period.
    pub fn is_valid(&self, fingerprint: &KeyFingerprint, grace_period_secs: u64) -> bool {
        let path = self.session_path(fingerprint);
        let Ok(content) = std::fs::read_to_string(&path) else {
            return false;
        };
        let Ok(session) = serde_json::from_str::<MfaSession>(&content) else {
            return false;
        };

        // Verify HMAC
        let expected_hmac = compute_hmac(&session.verified_at, &fingerprint.0);
        if session.hmac != expected_hmac {
            return false;
        }

        let elapsed = Utc::now()
            .signed_duration_since(session.verified_at)
            .num_seconds();
        elapsed >= 0 && (elapsed as u64) < grace_period_secs
    }

    /// Create a new MFA session.
    pub fn create(&self, fingerprint: &KeyFingerprint) -> Result<()> {
        std::fs::create_dir_all(&self.session_dir)?;

        let now = Utc::now();
        let hmac = compute_hmac(&now, &fingerprint.0);
        let session = MfaSession {
            verified_at: now,
            hmac,
        };

        let json = serde_json::to_string(&session)
            .map_err(|e| crate::error::SigynError::Serialization(e.to_string()))?;
        std::fs::write(self.session_path(fingerprint), json)?;
        Ok(())
    }

    /// Clear (delete) an MFA session.
    pub fn clear(&self, fingerprint: &KeyFingerprint) -> Result<()> {
        let path = self.session_path(fingerprint);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Compute an HMAC-like tag over the timestamp using blake3 keyed hash.
/// Uses the fingerprint bytes (padded to 32 bytes) as the key.
fn compute_hmac(timestamp: &DateTime<Utc>, fingerprint_bytes: &[u8; 16]) -> String {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(fingerprint_bytes);
    let hasher = blake3::Hasher::new_keyed(&key);
    let ts_str = timestamp.to_rfc3339();
    let mut h = hasher;
    h.update(ts_str.as_bytes());
    h.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        let store = MfaSessionStore::new(dir.path().to_path_buf());
        let fp = KeyFingerprint([1u8; 16]);

        assert!(!store.is_valid(&fp, DEFAULT_GRACE_PERIOD_SECS));

        store.create(&fp).unwrap();
        assert!(store.is_valid(&fp, DEFAULT_GRACE_PERIOD_SECS));

        // With a 0-second grace period, should be expired
        assert!(!store.is_valid(&fp, 0));

        store.clear(&fp).unwrap();
        assert!(!store.is_valid(&fp, DEFAULT_GRACE_PERIOD_SECS));
    }

    #[test]
    fn test_tampered_session_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = MfaSessionStore::new(dir.path().to_path_buf());
        let fp = KeyFingerprint([2u8; 16]);

        store.create(&fp).unwrap();

        // Tamper with the session file
        let path = store.session_path(&fp);
        let mut session: MfaSession =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        session.verified_at = Utc::now() + chrono::Duration::hours(24);
        std::fs::write(&path, serde_json::to_string(&session).unwrap()).unwrap();

        assert!(!store.is_valid(&fp, DEFAULT_GRACE_PERIOD_SECS));
    }
}
