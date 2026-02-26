use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default MFA session grace period: 1 hour.
pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSession {
    pub verified_at: DateTime<Utc>,
    /// HMAC of verified_at using fingerprint bytes as key, for tamper detection.
    pub hmac: String,
}

/// Compute an HMAC-like tag over the timestamp using blake3 keyed hash.
/// Uses a 32-byte secret key (derived from the device key via HKDF).
pub fn compute_hmac(timestamp: &DateTime<Utc>, hmac_key: &[u8; 32]) -> String {
    let hasher = blake3::Hasher::new_keyed(hmac_key);
    let ts_str = timestamp.to_rfc3339();
    let mut h = hasher;
    h.update(ts_str.as_bytes());
    h.finalize().to_hex().to_string()
}
