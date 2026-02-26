use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::error::{Result, SigynError};

const ARGON2_M_COST: u32 = 131072; // 128 MB
const ARGON2_T_COST: u32 = 4;
const ARGON2_P_COST: u32 = 4;

/// Minimum acceptable KDF parameters to prevent downgrade attacks.
/// These are checked when loading identity files to reject weak parameters.
const MIN_M_COST: u32 = 65536; // 64 MB minimum
const MIN_T_COST: u32 = 3;
const MIN_P_COST: u32 = 1;

fn argon2_instance() -> Argon2<'static> {
    let (m, t, p) = if cfg!(feature = "fast-kdf") {
        (1024, 1, 1)
    } else {
        (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
    };
    let params = Params::new(m, t, p, Some(32)).expect("hardcoded argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Validate that KDF parameters meet minimum security thresholds.
/// This prevents downgrade attacks where an attacker replaces an identity file
/// with one using weak KDF parameters.
///
/// Note: when `fast-kdf` feature is enabled (for testing), this check is relaxed.
pub fn validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<()> {
    if cfg!(feature = "fast-kdf") {
        return Ok(());
    }
    if m_cost < MIN_M_COST {
        return Err(SigynError::PolicyViolation(format!(
            "KDF memory cost {} is below minimum {} — identity file may be tampered",
            m_cost, MIN_M_COST
        )));
    }
    if t_cost < MIN_T_COST {
        return Err(SigynError::PolicyViolation(format!(
            "KDF time cost {} is below minimum {} — identity file may be tampered",
            t_cost, MIN_T_COST
        )));
    }
    if p_cost < MIN_P_COST {
        return Err(SigynError::PolicyViolation(format!(
            "KDF parallelism {} is below minimum {} — identity file may be tampered",
            p_cost, MIN_P_COST
        )));
    }
    Ok(())
}

/// Wrap a private key with a passphrase-derived key.
///
/// # Security
/// The caller is responsible for zeroizing the passphrase `String` after this
/// call returns (e.g. by using `zeroize::Zeroize` on the owned `String`).
/// This function cannot zeroize the borrowed `&str`.
pub fn wrap_private_key(key: &[u8; 32], passphrase: &str, salt: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, KeyInit};

    let mut derived = [0u8; 32];
    let argon2 = argon2_instance();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|e| SigynError::Encryption(e.to_string()))?;
    derived.zeroize();

    let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.as_slice(),
                aad: salt,
            },
        )
        .map_err(|e| SigynError::Encryption(e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Unwrap a private key using a passphrase-derived key.
///
/// # Security
/// The caller is responsible for zeroizing the passphrase `String` after this
/// call returns (e.g. by using `zeroize::Zeroize` on the owned `String`).
pub fn unwrap_private_key(wrapped: &[u8], passphrase: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

    if wrapped.len() < 12 {
        return Err(SigynError::Decryption("wrapped key too short".into()));
    }

    let (nonce_bytes, ciphertext) = wrapped.split_at(12);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let mut derived = [0u8; 32];
    let argon2 = argon2_instance();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|e| SigynError::Decryption(e.to_string()))?;
    derived.zeroize();

    let mut plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: salt,
            },
        )
        .map_err(|_| SigynError::InvalidPassphrase)?;

    let mut key = [0u8; 32];
    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(SigynError::Decryption("unexpected key length".into()));
    }
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::nonce::generate_salt;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let key = [42u8; 32];
        let passphrase = "test-passphrase";
        let salt = generate_salt();
        let wrapped = wrap_private_key(&key, passphrase, &salt).unwrap();
        let unwrapped = unwrap_private_key(&wrapped, passphrase, &salt).unwrap();
        assert_eq!(key, unwrapped);
    }

    #[test]
    fn test_wrong_passphrase() {
        let key = [42u8; 32];
        let salt = generate_salt();
        let wrapped = wrap_private_key(&key, "correct", &salt).unwrap();
        let result = unwrap_private_key(&wrapped, "wrong", &salt);
        assert!(result.is_err());
    }
}
