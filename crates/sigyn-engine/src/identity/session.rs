use std::path::PathBuf;

use chrono::Utc;

use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::error::Result;
pub use sigyn_core::identity::session::{compute_hmac, MfaSession, DEFAULT_GRACE_PERIOD_SECS};

/// Constant-time byte equality comparison to prevent timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct MfaSessionStore {
    session_dir: PathBuf,
    /// HMAC key derived from the device key (not the public fingerprint).
    hmac_key: [u8; 32],
}

impl MfaSessionStore {
    pub fn new(session_dir: PathBuf, hmac_key: [u8; 32]) -> Self {
        Self {
            session_dir,
            hmac_key,
        }
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

        // Verify HMAC using constant-time comparison to prevent timing attacks
        let expected_hmac = compute_hmac(&session.verified_at, &self.hmac_key);
        if !constant_time_eq(session.hmac.as_bytes(), expected_hmac.as_bytes()) {
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

        // Restrict session directory permissions to owner-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&self.session_dir, std::fs::Permissions::from_mode(0o700));
        }

        let now = Utc::now();
        let hmac = compute_hmac(&now, &self.hmac_key);
        let session = MfaSession {
            verified_at: now,
            hmac,
        };

        let json = serde_json::to_string(&session)
            .map_err(|e| sigyn_core::error::SigynError::Serialization(e.to_string()))?;

        let path = self.session_path(fingerprint);
        std::fs::write(&path, json)?;

        // Restrict session file permissions to owner-only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        let hmac_key = [0x42u8; 32];
        let store = MfaSessionStore::new(dir.path().to_path_buf(), hmac_key);
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
        let hmac_key = [0x42u8; 32];
        let store = MfaSessionStore::new(dir.path().to_path_buf(), hmac_key);
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

    #[test]
    fn test_wrong_hmac_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let hmac_key1 = [0x42u8; 32];
        let hmac_key2 = [0x99u8; 32];
        let store1 = MfaSessionStore::new(dir.path().to_path_buf(), hmac_key1);
        let store2 = MfaSessionStore::new(dir.path().to_path_buf(), hmac_key2);
        let fp = KeyFingerprint([3u8; 16]);

        store1.create(&fp).unwrap();
        assert!(store1.is_valid(&fp, DEFAULT_GRACE_PERIOD_SECS));
        // Different key should reject the session
        assert!(!store2.is_valid(&fp, DEFAULT_GRACE_PERIOD_SECS));
    }
}
