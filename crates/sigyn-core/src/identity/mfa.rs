use serde::{Deserialize, Serialize};

use crate::error::{Result, SigynError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaState {
    /// Base32-encoded TOTP secret
    pub totp_secret: String,
    /// Blake3 hashes of backup codes
    pub backup_codes: Vec<String>,
    /// When MFA was enabled
    pub enabled_at: chrono::DateTime<chrono::Utc>,
}

/// Derive a 32-byte encryption key from the identity's X25519 private key bytes
/// using HKDF-SHA256 with info context `b"mfa-state"`.
pub fn derive_mfa_key(identity_key: &[u8; 32]) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, identity_key);
    let mut okm = [0u8; 32];
    hk.expand(b"mfa-state", &mut okm)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

/// Hash a backup code with blake3 for storage.
pub fn hash_backup_code(code: &str) -> String {
    blake3::hash(code.as_bytes()).to_hex().to_string()
}

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

/// Verify a backup code against a list of hashed codes.
/// Returns the index of the matching code if found.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_backup_code(code: &str, hashed_codes: &[String]) -> Option<usize> {
    let hash = hash_backup_code(code);
    // Check all codes (don't short-circuit) to prevent timing leaks
    let mut found_index: Option<usize> = None;
    for (i, h) in hashed_codes.iter().enumerate() {
        if constant_time_eq(hash.as_bytes(), h.as_bytes()) {
            found_index = Some(i);
        }
    }
    found_index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_code_hashing() {
        let code = "abc12345";
        let hash = hash_backup_code(code);
        assert_eq!(verify_backup_code(code, &[hash.clone()]), Some(0));
        assert_eq!(verify_backup_code("wrong", &[hash]), None);
    }
}
