use serde::{Deserialize, Serialize};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{SigynError, Result};
use super::keys::{X25519PrivateKey, X25519PublicKey, KeyFingerprint};

#[derive(Clone, Serialize, Deserialize)]
pub struct RecipientSlot {
    pub fingerprint: KeyFingerprint,
    pub ephemeral_pubkey: X25519PublicKey,
    pub encrypted_master_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EnvelopeHeader {
    pub slots: Vec<RecipientSlot>,
}

fn derive_slot_key(shared_secret: &[u8; 32], vault_id: &Uuid) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"sigyn-envelope-v1", &mut okm)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

fn encrypt_slot(master_key: &[u8; 32], slot_key: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadCore, aead::Aead};

    let cipher = ChaCha20Poly1305::new_from_slice(slot_key)
        .map_err(|e| SigynError::Encryption(e.to_string()))?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, master_key.as_slice())
        .map_err(|e| SigynError::Encryption(e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_slot(encrypted: &[u8], slot_key: &[u8; 32]) -> Result<[u8; 32]> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
    use chacha20poly1305::aead::generic_array::GenericArray;

    if encrypted.len() < 12 {
        return Err(SigynError::Decryption("slot data too short".into()));
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(slot_key)
        .map_err(|e| SigynError::Decryption(e.to_string()))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SigynError::Decryption("failed to decrypt master key slot".into()))?;

    let mut key = [0u8; 32];
    if plaintext.len() != 32 {
        return Err(SigynError::Decryption("unexpected master key length".into()));
    }
    key.copy_from_slice(&plaintext);
    Ok(key)
}

pub fn seal_master_key(
    master_key: &[u8; 32],
    recipients: &[X25519PublicKey],
    vault_id: Uuid,
) -> Result<EnvelopeHeader> {
    let mut slots = Vec::with_capacity(recipients.len());

    for recipient_pubkey in recipients {
        let ephemeral = X25519PrivateKey::generate();
        let ephemeral_pub = ephemeral.public_key();
        let shared = ephemeral.diffie_hellman(recipient_pubkey);
        let slot_key = derive_slot_key(&shared, &vault_id)?;
        let encrypted = encrypt_slot(master_key, &slot_key)?;

        slots.push(RecipientSlot {
            fingerprint: recipient_pubkey.fingerprint(),
            ephemeral_pubkey: ephemeral_pub,
            encrypted_master_key: encrypted,
        });
    }

    Ok(EnvelopeHeader { slots })
}

pub fn unseal_master_key(
    header: &EnvelopeHeader,
    private_key: &X25519PrivateKey,
    vault_id: Uuid,
) -> Result<[u8; 32]> {
    let my_fingerprint = private_key.public_key().fingerprint();

    for slot in &header.slots {
        if slot.fingerprint == my_fingerprint {
            let shared = private_key.diffie_hellman(&slot.ephemeral_pubkey);
            let slot_key = derive_slot_key(&shared, &vault_id)?;
            return decrypt_slot(&slot.encrypted_master_key, &slot_key);
        }
    }

    Err(SigynError::NoMatchingSlot)
}

pub fn add_recipient(
    header: &mut EnvelopeHeader,
    master_key: &[u8; 32],
    pubkey: &X25519PublicKey,
    vault_id: Uuid,
) -> Result<()> {
    let ephemeral = X25519PrivateKey::generate();
    let ephemeral_pub = ephemeral.public_key();
    let shared = ephemeral.diffie_hellman(pubkey);
    let slot_key = derive_slot_key(&shared, &vault_id)?;
    let encrypted = encrypt_slot(master_key, &slot_key)?;

    header.slots.push(RecipientSlot {
        fingerprint: pubkey.fingerprint(),
        ephemeral_pubkey: ephemeral_pub,
        encrypted_master_key: encrypted,
    });
    Ok(())
}

pub fn remove_recipient(header: &mut EnvelopeHeader, fingerprint: &KeyFingerprint) {
    header.slots.retain(|s| &s.fingerprint != fingerprint);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let master_key = [0xABu8; 32];
        let vault_id = Uuid::new_v4();
        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();

        let header = seal_master_key(
            &master_key,
            &[alice.public_key(), bob.public_key()],
            vault_id,
        )
        .unwrap();

        assert_eq!(header.slots.len(), 2);

        let recovered_alice = unseal_master_key(&header, &alice, vault_id).unwrap();
        let recovered_bob = unseal_master_key(&header, &bob, vault_id).unwrap();
        assert_eq!(master_key, recovered_alice);
        assert_eq!(master_key, recovered_bob);
    }

    #[test]
    fn test_wrong_key_fails() {
        let master_key = [0xABu8; 32];
        let vault_id = Uuid::new_v4();
        let alice = X25519PrivateKey::generate();
        let eve = X25519PrivateKey::generate();

        let header = seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();
        assert!(unseal_master_key(&header, &eve, vault_id).is_err());
    }

    #[test]
    fn test_add_remove_recipient() {
        let master_key = [0xCDu8; 32];
        let vault_id = Uuid::new_v4();
        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();

        let mut header = seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();
        assert_eq!(header.slots.len(), 1);

        add_recipient(&mut header, &master_key, &bob.public_key(), vault_id).unwrap();
        assert_eq!(header.slots.len(), 2);

        let recovered = unseal_master_key(&header, &bob, vault_id).unwrap();
        assert_eq!(master_key, recovered);

        remove_recipient(&mut header, &bob.public_key().fingerprint());
        assert_eq!(header.slots.len(), 1);
        assert!(unseal_master_key(&header, &bob, vault_id).is_err());
    }
}
