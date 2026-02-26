use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use super::vault_cipher::VaultCipher;
use crate::error::{Result, SigynError};

/// Magic bytes for AEAD-sealed files.
pub const SEALED_MAGIC: &[u8; 4] = b"SGYN";
/// Magic bytes for Ed25519-signed files.
pub const SIGNED_MAGIC: &[u8; 4] = b"SGSN";
/// Current sealed file format version.
pub const SEALED_VERSION: u8 = 0x01;

/// Check whether raw data begins with the SGYN sealed magic header.
pub fn is_sealed(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == SEALED_MAGIC
}

/// Check whether raw data begins with the SGSN signed magic header.
pub fn is_signed(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == SIGNED_MAGIC
}

/// Encrypt plaintext into the sealed file format:
/// `[SGYN 4B] [version 1B] [nonce+ciphertext from VaultCipher]`
///
/// The `aad` is passed through to ChaCha20-Poly1305 for additional authenticated data.
pub fn sealed_encrypt(cipher: &VaultCipher, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let encrypted = cipher.encrypt(plaintext, aad)?;
    let mut out = Vec::with_capacity(5 + encrypted.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.push(SEALED_VERSION);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Decrypt a sealed file. Verifies magic header, then delegates to VaultCipher.
pub fn sealed_decrypt(cipher: &VaultCipher, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 5 {
        return Err(SigynError::Decryption("sealed data too short".into()));
    }
    if &data[..4] != SEALED_MAGIC {
        return Err(SigynError::Decryption(
            "invalid sealed magic header — file may be tampered or corrupted".into(),
        ));
    }
    if data[4] != SEALED_VERSION {
        return Err(SigynError::Decryption(format!(
            "unsupported sealed version: {}",
            data[4]
        )));
    }
    cipher.decrypt(&data[5..], aad)
}

/// Derive a VaultCipher from a root key and a context label (no salt).
///
/// Used for Tier A (device key → per-file ciphers).
pub fn derive_file_cipher(key: &[u8; 32], context: &[u8]) -> Result<VaultCipher> {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;
    Ok(VaultCipher::new(okm))
}

/// Derive a VaultCipher from a root key, context label, and a vault-specific salt.
///
/// Used for Tier C (master key → per-file ciphers within a vault).
pub fn derive_file_cipher_with_salt(
    key: &[u8; 32],
    context: &[u8],
    salt: &Uuid,
) -> Result<VaultCipher> {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), key);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;
    Ok(VaultCipher::new(okm))
}

/// Wrap Ed25519-signed data in the signed file format:
/// `[SGSN 4B] [version 1B] [payload] [signature 64B]`
///
/// The signature covers `blake3(payload || extra_context)`.
pub fn signed_wrap(
    payload: &[u8],
    signing_key: &super::keys::SigningKeyPair,
    extra_context: &[u8],
) -> Vec<u8> {
    let mut hash_input = Vec::with_capacity(payload.len() + extra_context.len());
    hash_input.extend_from_slice(payload);
    hash_input.extend_from_slice(extra_context);
    let hash = blake3::hash(&hash_input);
    let sig = signing_key.sign(hash.as_bytes());

    let mut out = Vec::with_capacity(5 + payload.len() + 64);
    out.extend_from_slice(SIGNED_MAGIC);
    out.push(SEALED_VERSION);
    out.extend_from_slice(payload);
    out.extend_from_slice(&sig);
    out
}

/// Verify and unwrap a signed file. Returns the payload bytes on success.
///
/// Verifies that:
/// 1. Magic header is SGSN
/// 2. Ed25519 signature over `blake3(payload || extra_context)` is valid
pub fn signed_unwrap(
    data: &[u8],
    verifying_key: &super::keys::VerifyingKeyWrapper,
    extra_context: &[u8],
) -> Result<Vec<u8>> {
    if data.len() < 5 + 64 {
        return Err(SigynError::Decryption("signed data too short".into()));
    }
    if &data[..4] != SIGNED_MAGIC {
        return Err(SigynError::Decryption(
            "invalid signed magic header — file may be tampered or corrupted".into(),
        ));
    }
    if data[4] != SEALED_VERSION {
        return Err(SigynError::Decryption(format!(
            "unsupported signed version: {}",
            data[4]
        )));
    }

    let payload = &data[5..data.len() - 64];
    let sig_bytes = &data[data.len() - 64..];

    let mut hash_input = Vec::with_capacity(payload.len() + extra_context.len());
    hash_input.extend_from_slice(payload);
    hash_input.extend_from_slice(extra_context);
    let hash = blake3::hash(&hash_input);

    verifying_key.verify(hash.as_bytes(), sig_bytes)?;

    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SigningKeyPair;

    #[test]
    fn test_sealed_roundtrip() {
        let cipher = VaultCipher::generate();
        let plaintext = b"hello world";
        let aad = b"test-context";

        let sealed = sealed_encrypt(&cipher, plaintext, aad).unwrap();
        assert!(is_sealed(&sealed));
        assert!(!is_signed(&sealed));

        let decrypted = sealed_decrypt(&cipher, &sealed, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_sealed_wrong_key_fails() {
        let cipher1 = VaultCipher::generate();
        let cipher2 = VaultCipher::generate();
        let sealed = sealed_encrypt(&cipher1, b"secret", b"aad").unwrap();
        assert!(sealed_decrypt(&cipher2, &sealed, b"aad").is_err());
    }

    #[test]
    fn test_sealed_wrong_aad_fails() {
        let cipher = VaultCipher::generate();
        let sealed = sealed_encrypt(&cipher, b"secret", b"aad1").unwrap();
        assert!(sealed_decrypt(&cipher, &sealed, b"aad2").is_err());
    }

    #[test]
    fn test_sealed_tamper_detected() {
        let cipher = VaultCipher::generate();
        let mut sealed = sealed_encrypt(&cipher, b"secret", b"aad").unwrap();
        if let Some(last) = sealed.last_mut() {
            *last ^= 0xFF;
        }
        assert!(sealed_decrypt(&cipher, &sealed, b"aad").is_err());
    }

    #[test]
    fn test_is_sealed_plaintext() {
        assert!(!is_sealed(b"[default_vault]"));
        assert!(!is_sealed(b"abc"));
        assert!(!is_sealed(b""));
    }

    #[test]
    fn test_derive_file_cipher() {
        let key = [0x42u8; 32];
        let c1 = derive_file_cipher(&key, b"sigyn-config-v1").unwrap();
        let c2 = derive_file_cipher(&key, b"sigyn-context-v1").unwrap();

        // Different contexts produce different ciphers
        let enc1 = c1.encrypt(b"test", b"").unwrap();
        assert!(c2.decrypt(&enc1, b"").is_err());
    }

    #[test]
    fn test_derive_file_cipher_with_salt() {
        let key = [0x42u8; 32];
        let salt1 = Uuid::new_v4();
        let salt2 = Uuid::new_v4();
        let c1 = derive_file_cipher_with_salt(&key, b"sigyn-manifest-v1", &salt1).unwrap();
        let c2 = derive_file_cipher_with_salt(&key, b"sigyn-manifest-v1", &salt2).unwrap();

        // Different salts produce different ciphers
        let enc1 = c1.encrypt(b"test", b"").unwrap();
        assert!(c2.decrypt(&enc1, b"").is_err());
    }

    #[test]
    fn test_signed_roundtrip() {
        let kp = SigningKeyPair::generate();
        let vk = kp.verifying_key();
        let payload = b"some cbor data here";
        let context = b"vault-id-bytes";

        let wrapped = signed_wrap(payload, &kp, context);
        assert!(is_signed(&wrapped));
        assert!(!is_sealed(&wrapped));

        let recovered = signed_unwrap(&wrapped, &vk, context).unwrap();
        assert_eq!(payload.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_signed_wrong_key_fails() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();
        let wrapped = signed_wrap(b"data", &kp1, b"ctx");
        assert!(signed_unwrap(&wrapped, &kp2.verifying_key(), b"ctx").is_err());
    }

    #[test]
    fn test_signed_wrong_context_fails() {
        let kp = SigningKeyPair::generate();
        let wrapped = signed_wrap(b"data", &kp, b"ctx1");
        assert!(signed_unwrap(&wrapped, &kp.verifying_key(), b"ctx2").is_err());
    }

    #[test]
    fn test_signed_tamper_detected() {
        let kp = SigningKeyPair::generate();
        let mut wrapped = signed_wrap(b"data", &kp, b"ctx");
        // Tamper with payload byte
        wrapped[6] ^= 0xFF;
        assert!(signed_unwrap(&wrapped, &kp.verifying_key(), b"ctx").is_err());
    }
}
