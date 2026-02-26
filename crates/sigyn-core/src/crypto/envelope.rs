use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

use super::keys::{KeyFingerprint, X25519PrivateKey, X25519PublicKey};
use crate::error::{Result, SigynError};

/// Build AAD bytes binding ciphertext to a specific recipient and vault.
fn slot_aad(fingerprint: &KeyFingerprint, vault_id: &Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(&fingerprint.0);
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecipientSlot {
    pub fingerprint: KeyFingerprint,
    pub ephemeral_pubkey: X25519PublicKey,
    pub encrypted_master_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EnvelopeHeader {
    pub slots: Vec<RecipientSlot>,
    /// Vault UUID — allows reading vault_id from members.cbor before decrypting vault.toml.
    #[serde(default)]
    pub vault_id: Option<Uuid>,
}

fn derive_slot_key(shared_secret: &[u8; 32], vault_id: &Uuid) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"sigyn-envelope-v1", &mut okm)
        .map_err(|e| SigynError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

fn encrypt_slot(master_key: &[u8; 32], slot_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, KeyInit};

    let cipher = ChaCha20Poly1305::new_from_slice(slot_key)
        .map_err(|e| SigynError::Encryption(e.to_string()))?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: master_key.as_slice(),
                aad,
            },
        )
        .map_err(|e| SigynError::Encryption(e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_slot(encrypted: &[u8], slot_key: &[u8; 32], aad: &[u8]) -> Result<[u8; 32]> {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::Payload;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

    if encrypted.len() < 12 {
        return Err(SigynError::Decryption("slot data too short".into()));
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(slot_key)
        .map_err(|e| SigynError::Decryption(e.to_string()))?;
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SigynError::Decryption("failed to decrypt master key slot".into()))?;

    let mut key = [0u8; 32];
    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(SigynError::Decryption(
            "unexpected master key length".into(),
        ));
    }
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
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
        let mut shared = ephemeral.diffie_hellman(recipient_pubkey);
        let slot_key = derive_slot_key(&shared, &vault_id)?;
        shared.zeroize();
        let fp = recipient_pubkey.fingerprint();
        let aad = slot_aad(&fp, &vault_id);
        let encrypted = encrypt_slot(master_key, &slot_key, &aad)?;

        slots.push(RecipientSlot {
            fingerprint: fp,
            ephemeral_pubkey: ephemeral_pub,
            encrypted_master_key: encrypted,
        });
    }

    Ok(EnvelopeHeader {
        slots,
        vault_id: Some(vault_id),
    })
}

pub fn unseal_master_key(
    header: &EnvelopeHeader,
    private_key: &X25519PrivateKey,
    vault_id: Uuid,
) -> Result<[u8; 32]> {
    let my_fingerprint = private_key.public_key().fingerprint();

    for slot in &header.slots {
        if slot.fingerprint == my_fingerprint {
            let mut shared = private_key.diffie_hellman(&slot.ephemeral_pubkey);
            let slot_key = derive_slot_key(&shared, &vault_id)?;
            shared.zeroize();
            let aad = slot_aad(&slot.fingerprint, &vault_id);
            return decrypt_slot(&slot.encrypted_master_key, &slot_key, &aad);
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
    let mut shared = ephemeral.diffie_hellman(pubkey);
    let slot_key = derive_slot_key(&shared, &vault_id)?;
    shared.zeroize();
    let fp = pubkey.fingerprint();
    let aad = slot_aad(&fp, &vault_id);
    let encrypted = encrypt_slot(master_key, &slot_key, &aad)?;

    header.slots.push(RecipientSlot {
        fingerprint: fp,
        ephemeral_pubkey: ephemeral_pub,
        encrypted_master_key: encrypted,
    });
    Ok(())
}

pub fn remove_recipient(header: &mut EnvelopeHeader, fingerprint: &KeyFingerprint) {
    header.slots.retain(|s| &s.fingerprint != fingerprint);
}

/// Serialize an EnvelopeHeader to CBOR, then wrap it in the SGSN signed format.
///
/// The signature covers `blake3(cbor_bytes || vault_id_bytes)`.
pub fn sign_header(
    header: &EnvelopeHeader,
    signing_key: &super::keys::SigningKeyPair,
    vault_id: Uuid,
) -> Result<Vec<u8>> {
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(header, &mut cbor_bytes)
        .map_err(|e| SigynError::CborEncode(e.to_string()))?;
    Ok(super::sealed::signed_wrap(
        &cbor_bytes,
        signing_key,
        vault_id.as_bytes(),
    ))
}

/// Verify a signed members file and deserialize the EnvelopeHeader.
///
/// Requires the SGSN signed format — unsigned data is rejected.
/// A verifying key is required; pass `None` only for the initial bootstrap
/// read where vault_id must be extracted before the signer is known
/// (use `extract_header_unverified` for that case).
pub fn verify_and_load_header(
    data: &[u8],
    vault_id: Uuid,
    verifying_key: &super::keys::VerifyingKeyWrapper,
) -> Result<EnvelopeHeader> {
    if !super::sealed::is_signed(data) {
        return Err(SigynError::Decryption(
            "members file is not in signed format (SGSN) — file may be tampered or corrupted"
                .into(),
        ));
    }
    let cbor_bytes = super::sealed::signed_unwrap(data, verifying_key, vault_id.as_bytes())?;
    ciborium::from_reader(cbor_bytes.as_slice()).map_err(|e| SigynError::CborDecode(e.to_string()))
}

/// Extract an EnvelopeHeader without signature verification.
///
/// Used ONLY during the bootstrap sequence to read vault_id from the header
/// before the signer's key is known. The caller MUST subsequently verify
/// the header with `verify_and_load_header` once they have the verifying key.
///
/// Rejects data that is not in SGSN signed format.
pub fn extract_header_unverified(data: &[u8]) -> Result<EnvelopeHeader> {
    if !super::sealed::is_signed(data) {
        return Err(SigynError::Decryption(
            "members file is not in signed format (SGSN) — file may be tampered or corrupted"
                .into(),
        ));
    }
    // 5 bytes header + payload + 64 bytes sig
    if data.len() < 69 {
        return Err(SigynError::Decryption("signed data too short".into()));
    }
    let cbor_bytes = &data[5..data.len() - 64];
    ciborium::from_reader(cbor_bytes).map_err(|e| SigynError::CborDecode(e.to_string()))
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
