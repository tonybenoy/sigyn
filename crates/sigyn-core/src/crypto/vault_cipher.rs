use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::nonce::generate_nonce;
use crate::error::{Result, SigynError};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultCipher {
    key: [u8; 32],
}

impl VaultCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self { key }
    }

    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Payload;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| SigynError::Encryption(e.to_string()))?;
        let nonce_bytes = generate_nonce();
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| SigynError::Encryption(e.to_string()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, encrypted: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Payload;

        if encrypted.len() < 12 {
            return Err(SigynError::Decryption("ciphertext too short".into()));
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = GenericArray::from_slice(nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| SigynError::Decryption(e.to_string()))?;

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|_| SigynError::Decryption("AEAD decryption failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = VaultCipher::generate();
        let plaintext = b"DATABASE_URL=postgres://localhost/mydb";
        let aad = b"dev";

        let encrypted = cipher.encrypt(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&encrypted, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let cipher = VaultCipher::generate();
        let encrypted = cipher.encrypt(b"secret", b"dev").unwrap();
        assert!(cipher.decrypt(&encrypted, b"prod").is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let cipher1 = VaultCipher::generate();
        let cipher2 = VaultCipher::generate();
        let encrypted = cipher1.encrypt(b"secret", b"aad").unwrap();
        assert!(cipher2.decrypt(&encrypted, b"aad").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let cipher = VaultCipher::generate();
        let mut encrypted = cipher.encrypt(b"secret", b"aad").unwrap();
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }
        assert!(cipher.decrypt(&encrypted, b"aad").is_err());
    }
}
