use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;

/// Default MFA session grace period: 1 hour.
pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSession {
    pub verified_at: DateTime<Utc>,
    /// HMAC over the identity fingerprint and verified_at (keyed with a
    /// device-derived secret), for tamper detection and to bind the session
    /// to a single identity.
    pub hmac: String,
}

/// Compute an HMAC-like tag over the identity fingerprint and timestamp using
/// a blake3 keyed hash. Uses a 32-byte secret key (derived from the device key
/// via HKDF).
///
/// The fingerprint of the identity being verified MUST be mixed into the tag:
/// it binds the session to that identity, so a session file created for one
/// identity cannot be replayed for another (e.g. by copying `alice.session`
/// to `bob.session`).
pub fn compute_hmac(
    fingerprint: &KeyFingerprint,
    timestamp: &DateTime<Utc>,
    hmac_key: &[u8; 32],
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(hmac_key);
    // KeyFingerprint is fixed-length (16 bytes), so no length prefix is
    // needed to keep the input encoding unambiguous.
    hasher.update(&fingerprint.0);
    hasher.update(timestamp.to_rfc3339().as_bytes());
    hasher.finalize().to_hex().to_string()
}
