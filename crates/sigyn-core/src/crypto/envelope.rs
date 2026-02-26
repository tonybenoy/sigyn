use std::collections::BTreeMap;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::keys::{KeyFingerprint, X25519PrivateKey, X25519PublicKey};
use crate::error::{Result, SigynError};

/// Build AAD bytes binding ciphertext to a specific recipient and vault.
fn slot_aad(fingerprint: &KeyFingerprint, vault_id: &Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(&fingerprint.0);
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

/// Build AAD bytes binding ciphertext to a specific recipient, vault, and environment.
/// Layout: fingerprint(16) || vault_id(16) || env_name_len(4 LE) || env_name_bytes
fn env_slot_aad(fingerprint: &KeyFingerprint, vault_id: &Uuid, env_name: &str) -> Vec<u8> {
    let env_bytes = env_name.as_bytes();
    let mut aad = Vec::with_capacity(32 + 4 + env_bytes.len());
    aad.extend_from_slice(&fingerprint.0);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&(env_bytes.len() as u32).to_le_bytes());
    aad.extend_from_slice(env_bytes);
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
    /// Format version. Always 2 (per-env isolation).
    #[serde(default)]
    pub version: u8,

    /// Vault-level key slots (manifest, policy, audit). Every member gets one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vault_key_slots: Vec<RecipientSlot>,

    /// Per-environment key slots. Only members allowed for that env get a slot.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_slots: BTreeMap<String, Vec<RecipientSlot>>,

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

/// Create a single recipient slot for a given key.
fn make_slot(
    key: &[u8; 32],
    pubkey: &X25519PublicKey,
    vault_id: &Uuid,
    aad: &[u8],
) -> Result<RecipientSlot> {
    let ephemeral = X25519PrivateKey::generate();
    let ephemeral_pub = ephemeral.public_key();
    let mut shared = ephemeral.diffie_hellman(pubkey);
    let slot_key = Zeroizing::new(derive_slot_key(&shared, vault_id)?);
    shared.zeroize();
    let encrypted = encrypt_slot(key, &slot_key, aad)?;
    Ok(RecipientSlot {
        fingerprint: pubkey.fingerprint(),
        ephemeral_pubkey: ephemeral_pub,
        encrypted_master_key: encrypted,
    })
}

/// Build an envelope header with per-environment key isolation.
///
/// * `vault_key` — 32-byte key for manifest/policy/audit.
/// * `env_keys` — per-environment 32-byte keys.
/// * `vault_recipients` — public keys that get the vault key (all members).
/// * `env_recipients` — per-env map of public keys that get each env's key.
pub fn seal_v2(
    vault_key: &[u8; 32],
    env_keys: &BTreeMap<String, [u8; 32]>,
    vault_recipients: &[X25519PublicKey],
    env_recipients: &BTreeMap<String, Vec<X25519PublicKey>>,
    vault_id: Uuid,
) -> Result<EnvelopeHeader> {
    let mut vault_key_slots = Vec::with_capacity(vault_recipients.len());
    for pubkey in vault_recipients {
        let aad = slot_aad(&pubkey.fingerprint(), &vault_id);
        vault_key_slots.push(make_slot(vault_key, pubkey, &vault_id, &aad)?);
    }

    let mut env_slots = BTreeMap::new();
    for (env_name, env_key) in env_keys {
        let recipients = env_recipients.get(env_name).cloned().unwrap_or_default();
        let mut slots = Vec::with_capacity(recipients.len());
        for pubkey in &recipients {
            let aad = env_slot_aad(&pubkey.fingerprint(), &vault_id, env_name);
            slots.push(make_slot(env_key, pubkey, &vault_id, &aad)?);
        }
        env_slots.insert(env_name.clone(), slots);
    }

    Ok(EnvelopeHeader {
        version: 2,
        vault_key_slots,
        env_slots,
        vault_id: Some(vault_id),
    })
}

/// Unseal the vault-level key from a v2 header's `vault_key_slots`.
pub fn unseal_vault_key(
    header: &EnvelopeHeader,
    private_key: &X25519PrivateKey,
    vault_id: Uuid,
) -> Result<[u8; 32]> {
    let my_fp = private_key.public_key().fingerprint();
    for slot in &header.vault_key_slots {
        if slot.fingerprint == my_fp {
            let mut shared = private_key.diffie_hellman(&slot.ephemeral_pubkey);
            let slot_key = Zeroizing::new(derive_slot_key(&shared, &vault_id)?);
            shared.zeroize();
            let aad = slot_aad(&slot.fingerprint, &vault_id);
            return decrypt_slot(&slot.encrypted_master_key, &slot_key, &aad);
        }
    }
    Err(SigynError::NoMatchingSlot)
}

/// Unseal a specific environment's key from a v2 header's `env_slots`.
pub fn unseal_env_key(
    header: &EnvelopeHeader,
    env_name: &str,
    private_key: &X25519PrivateKey,
    vault_id: Uuid,
) -> Result<[u8; 32]> {
    let my_fp = private_key.public_key().fingerprint();
    let slots = header
        .env_slots
        .get(env_name)
        .ok_or(SigynError::NoMatchingSlot)?;
    for slot in slots {
        if slot.fingerprint == my_fp {
            let mut shared = private_key.diffie_hellman(&slot.ephemeral_pubkey);
            let slot_key = Zeroizing::new(derive_slot_key(&shared, &vault_id)?);
            shared.zeroize();
            let aad = env_slot_aad(&slot.fingerprint, &vault_id, env_name);
            return decrypt_slot(&slot.encrypted_master_key, &slot_key, &aad);
        }
    }
    Err(SigynError::NoMatchingSlot)
}

/// Unseal a header: returns `(vault_key, {env_name: env_key, ...})`.
///
/// Unseals the vault-level key and all environment keys the caller has access to.
#[allow(clippy::type_complexity)]
pub fn unseal_header(
    header: &EnvelopeHeader,
    private_key: &X25519PrivateKey,
    vault_id: Uuid,
    requested_envs: &[String],
) -> Result<([u8; 32], BTreeMap<String, [u8; 32]>)> {
    let vault_key = unseal_vault_key(header, private_key, vault_id)?;
    let mut env_keys = BTreeMap::new();
    for env_name in requested_envs {
        if let Ok(ek) = unseal_env_key(header, env_name, private_key, vault_id) {
            env_keys.insert(env_name.clone(), ek);
        }
    }
    // Also try all env_slots the user has access to
    for env_name in header.env_slots.keys() {
        if !env_keys.contains_key(env_name) {
            if let Ok(ek) = unseal_env_key(header, env_name, private_key, vault_id) {
                env_keys.insert(env_name.clone(), ek);
            }
        }
    }
    Ok((vault_key, env_keys))
}

/// Add a vault-key recipient slot to a v2 header.
pub fn add_vault_key_recipient(
    header: &mut EnvelopeHeader,
    vault_key: &[u8; 32],
    pubkey: &X25519PublicKey,
    vault_id: Uuid,
) -> Result<()> {
    let fp = pubkey.fingerprint();
    if header.vault_key_slots.iter().any(|s| s.fingerprint == fp) {
        return Ok(());
    }
    let aad = slot_aad(&fp, &vault_id);
    header
        .vault_key_slots
        .push(make_slot(vault_key, pubkey, &vault_id, &aad)?);
    Ok(())
}

/// Add an env-key recipient slot to a v2 header.
pub fn add_env_recipient(
    header: &mut EnvelopeHeader,
    env_name: &str,
    env_key: &[u8; 32],
    pubkey: &X25519PublicKey,
    vault_id: Uuid,
) -> Result<()> {
    let fp = pubkey.fingerprint();
    let slots = header.env_slots.entry(env_name.to_string()).or_default();
    if slots.iter().any(|s| s.fingerprint == fp) {
        return Ok(());
    }
    let aad = env_slot_aad(&fp, &vault_id, env_name);
    slots.push(make_slot(env_key, pubkey, &vault_id, &aad)?);
    Ok(())
}

/// Remove a recipient from vault_key_slots and all env_slots.
pub fn remove_recipient_v2(header: &mut EnvelopeHeader, fingerprint: &KeyFingerprint) {
    header
        .vault_key_slots
        .retain(|s| &s.fingerprint != fingerprint);
    for slots in header.env_slots.values_mut() {
        slots.retain(|s| &s.fingerprint != fingerprint);
    }
}

/// Check if any vault_key_slots entry matches the given fingerprint.
pub fn has_recipient(header: &EnvelopeHeader, fingerprint: &KeyFingerprint) -> bool {
    header
        .vault_key_slots
        .iter()
        .any(|s| &s.fingerprint == fingerprint)
}

/// Remove all env_slots entries for a given environment name.
pub fn remove_env_slots(header: &mut EnvelopeHeader, env_name: &str) {
    header.env_slots.remove(env_name);
}

/// Remove a recipient from a single environment's slots.
pub fn remove_env_recipient(
    header: &mut EnvelopeHeader,
    env_name: &str,
    fingerprint: &KeyFingerprint,
) {
    if let Some(slots) = header.env_slots.get_mut(env_name) {
        slots.retain(|s| &s.fingerprint != fingerprint);
    }
}

/// Rotate an environment's key: generate a new random key and re-seal for given recipients.
/// Returns the new 32-byte env key.
pub fn rotate_env_key(
    header: &mut EnvelopeHeader,
    env_name: &str,
    recipients: &[X25519PublicKey],
    vault_id: Uuid,
) -> Result<[u8; 32]> {
    let mut new_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut new_key);

    let mut new_slots = Vec::with_capacity(recipients.len());
    for pubkey in recipients {
        let aad = env_slot_aad(&pubkey.fingerprint(), &vault_id, env_name);
        new_slots.push(make_slot(&new_key, pubkey, &vault_id, &aad)?);
    }
    header.env_slots.insert(env_name.to_string(), new_slots);
    Ok(new_key)
}

/// Rotate the vault-level key: generate a new random key and re-seal for remaining recipients.
/// This should be called during revocation to prevent revoked members from decrypting
/// metadata (manifest, policy) encrypted with the old vault key.
/// Returns the new 32-byte vault key.
pub fn rotate_vault_key(
    header: &mut EnvelopeHeader,
    remaining_pubkeys: &[(KeyFingerprint, X25519PublicKey)],
    vault_id: Uuid,
) -> Result<[u8; 32]> {
    let mut new_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut new_key);

    let mut new_slots = Vec::with_capacity(remaining_pubkeys.len());
    for (fp, pubkey) in remaining_pubkeys {
        let aad = slot_aad(fp, &vault_id);
        new_slots.push(make_slot(&new_key, pubkey, &vault_id, &aad)?);
    }
    header.vault_key_slots = new_slots;
    Ok(new_key)
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
    fn test_v2_seal_unseal_roundtrip() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0xAAu8; 32];
        let dev_key = [0xBBu8; 32];
        let prod_key = [0xCCu8; 32];

        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        env_keys.insert("prod".to_string(), prod_key);

        let mut env_recipients = BTreeMap::new();
        // Alice gets both envs, Bob only gets dev
        env_recipients.insert(
            "dev".to_string(),
            vec![alice.public_key(), bob.public_key()],
        );
        env_recipients.insert("prod".to_string(), vec![alice.public_key()]);

        let header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key(), bob.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        assert_eq!(header.version, 2);
        assert_eq!(header.vault_key_slots.len(), 2);

        // Alice can unseal everything
        let recovered_vk = unseal_vault_key(&header, &alice, vault_id).unwrap();
        assert_eq!(vault_key, recovered_vk);
        let recovered_dev = unseal_env_key(&header, "dev", &alice, vault_id).unwrap();
        assert_eq!(dev_key, recovered_dev);
        let recovered_prod = unseal_env_key(&header, "prod", &alice, vault_id).unwrap();
        assert_eq!(prod_key, recovered_prod);

        // Bob can unseal vault key and dev, but NOT prod
        let bob_vk = unseal_vault_key(&header, &bob, vault_id).unwrap();
        assert_eq!(vault_key, bob_vk);
        let bob_dev = unseal_env_key(&header, "dev", &bob, vault_id).unwrap();
        assert_eq!(dev_key, bob_dev);
        assert!(unseal_env_key(&header, "prod", &bob, vault_id).is_err());
    }

    #[test]
    fn test_v2_env_isolation() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0x11u8; 32];
        let dev_key = [0x22u8; 32];

        let alice = X25519PrivateKey::generate();
        let eve = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);

        let mut env_recipients = BTreeMap::new();
        env_recipients.insert("dev".to_string(), vec![alice.public_key()]);

        let header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        // Eve has no slots at all
        assert!(unseal_vault_key(&header, &eve, vault_id).is_err());
        assert!(unseal_env_key(&header, "dev", &eve, vault_id).is_err());
    }

    #[test]
    fn test_v2_add_remove_recipients() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0x33u8; 32];
        let dev_key = [0x44u8; 32];

        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        let mut env_recipients = BTreeMap::new();
        env_recipients.insert("dev".to_string(), vec![alice.public_key()]);

        let mut header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        // Add bob to vault + dev
        add_vault_key_recipient(&mut header, &vault_key, &bob.public_key(), vault_id).unwrap();
        add_env_recipient(&mut header, "dev", &dev_key, &bob.public_key(), vault_id).unwrap();

        assert_eq!(header.vault_key_slots.len(), 2);
        let bob_vk = unseal_vault_key(&header, &bob, vault_id).unwrap();
        assert_eq!(vault_key, bob_vk);
        let bob_dev = unseal_env_key(&header, "dev", &bob, vault_id).unwrap();
        assert_eq!(dev_key, bob_dev);

        // Remove bob from everything
        remove_recipient_v2(&mut header, &bob.public_key().fingerprint());
        assert_eq!(header.vault_key_slots.len(), 1);
        assert!(unseal_vault_key(&header, &bob, vault_id).is_err());
        assert!(unseal_env_key(&header, "dev", &bob, vault_id).is_err());
    }

    #[test]
    fn test_v2_remove_env_recipient() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0x55u8; 32];
        let dev_key = [0x66u8; 32];
        let prod_key = [0x77u8; 32];

        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        env_keys.insert("prod".to_string(), prod_key);
        let mut env_recipients = BTreeMap::new();
        env_recipients.insert(
            "dev".to_string(),
            vec![alice.public_key(), bob.public_key()],
        );
        env_recipients.insert(
            "prod".to_string(),
            vec![alice.public_key(), bob.public_key()],
        );

        let mut header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key(), bob.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        // Remove bob from prod only
        remove_env_recipient(&mut header, "prod", &bob.public_key().fingerprint());

        // Bob still has vault key and dev
        assert!(unseal_vault_key(&header, &bob, vault_id).is_ok());
        assert!(unseal_env_key(&header, "dev", &bob, vault_id).is_ok());
        // But not prod
        assert!(unseal_env_key(&header, "prod", &bob, vault_id).is_err());
    }

    #[test]
    fn test_v2_rotate_env_key() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0x88u8; 32];
        let dev_key = [0x99u8; 32];

        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        let mut env_recipients = BTreeMap::new();
        env_recipients.insert(
            "dev".to_string(),
            vec![alice.public_key(), bob.public_key()],
        );

        let mut header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key(), bob.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        // Rotate dev key for alice only (bob excluded)
        let new_key = rotate_env_key(&mut header, "dev", &[alice.public_key()], vault_id).unwrap();
        assert_ne!(dev_key, new_key);

        // Alice gets the new key
        let alice_dev = unseal_env_key(&header, "dev", &alice, vault_id).unwrap();
        assert_eq!(new_key, alice_dev);

        // Bob can no longer access dev
        assert!(unseal_env_key(&header, "dev", &bob, vault_id).is_err());
    }

    #[test]
    fn test_v2_unseal_header() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0xAAu8; 32];
        let dev_key = [0xBBu8; 32];

        let alice = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        let mut env_recipients = BTreeMap::new();
        env_recipients.insert("dev".to_string(), vec![alice.public_key()]);

        let header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        let (vk, ek) = unseal_header(&header, &alice, vault_id, &["dev".to_string()]).unwrap();
        assert_eq!(vault_key, vk);
        assert_eq!(dev_key, *ek.get("dev").unwrap());
    }

    #[test]
    fn test_v2_aad_prevents_cross_env_reuse() {
        // Verify that a slot encrypted for env "dev" cannot be moved to env "prod"
        let vault_id = Uuid::new_v4();
        let vault_key = [0xAAu8; 32];
        let dev_key = [0xBBu8; 32];
        let prod_key = [0xCCu8; 32];

        let alice = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        env_keys.insert("prod".to_string(), prod_key);
        let mut env_recipients = BTreeMap::new();
        env_recipients.insert("dev".to_string(), vec![alice.public_key()]);
        env_recipients.insert("prod".to_string(), vec![alice.public_key()]);

        let mut header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        // Swap dev slots into prod — this should fail to decrypt
        let dev_slots = header.env_slots.get("dev").unwrap().clone();
        header.env_slots.insert("prod".to_string(), dev_slots);

        // Trying to unseal "prod" with swapped dev slots should fail
        // because the AAD includes the env name
        assert!(unseal_env_key(&header, "prod", &alice, vault_id).is_err());
    }

    #[test]
    fn test_v2_idempotent_add() {
        let vault_id = Uuid::new_v4();
        let vault_key = [0x11u8; 32];
        let dev_key = [0x22u8; 32];

        let alice = X25519PrivateKey::generate();

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".to_string(), dev_key);
        let mut env_recipients = BTreeMap::new();
        env_recipients.insert("dev".to_string(), vec![alice.public_key()]);

        let mut header = seal_v2(
            &vault_key,
            &env_keys,
            &[alice.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        // Adding alice again should be idempotent
        add_vault_key_recipient(&mut header, &vault_key, &alice.public_key(), vault_id).unwrap();
        assert_eq!(header.vault_key_slots.len(), 1);

        add_env_recipient(&mut header, "dev", &dev_key, &alice.public_key(), vault_id).unwrap();
        assert_eq!(header.env_slots.get("dev").unwrap().len(), 1);
    }
}
