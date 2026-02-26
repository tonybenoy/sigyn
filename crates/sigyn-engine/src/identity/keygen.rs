use std::path::PathBuf;

use sigyn_core::crypto::keys::{KeyFingerprint, SigningKeyPair, X25519PrivateKey};
use sigyn_core::error::{Result, SigynError};
pub use sigyn_core::identity::keygen::{Identity, LoadedIdentity};
use sigyn_core::identity::profile::IdentityProfile;
use sigyn_core::identity::wrapping::WrappedIdentity;

/// Length of the BLAKE3 keyed MAC appended to identity files.
const IDENTITY_MAC_LEN: usize = 32;
/// Context for BLAKE3 keyed hash of identity files.
const IDENTITY_MAC_CONTEXT: &str = "sigyn-identity-file-v1";

pub struct IdentityStore {
    base_dir: PathBuf,
}

impl IdentityStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn identities_dir(&self) -> PathBuf {
        self.base_dir.join("identities")
    }

    fn identity_path(&self, fingerprint: &KeyFingerprint) -> PathBuf {
        self.identities_dir()
            .join(format!("{}.identity", fingerprint.to_hex()))
    }

    pub fn generate(&self, profile: IdentityProfile, passphrase: &str) -> Result<Identity> {
        let enc_private = X25519PrivateKey::generate();
        let enc_public = enc_private.public_key();

        let sign_kp = SigningKeyPair::generate();
        let sign_public = sign_kp.verifying_key();

        let wrapped = WrappedIdentity::wrap(
            &enc_private.to_bytes(),
            &sign_kp.to_bytes(),
            enc_public.clone(),
            sign_public.clone(),
            profile.clone(),
            passphrase,
        )?;

        let identity = Identity {
            fingerprint: enc_public.fingerprint(),
            profile,
            encryption_pubkey: enc_public,
            signing_pubkey: sign_public,
        };

        let dir = self.identities_dir();
        std::fs::create_dir_all(&dir)?;

        let path = self.identity_path(&identity.fingerprint);
        if path.exists() {
            return Err(SigynError::IdentityAlreadyExists(
                identity.fingerprint.to_hex(),
            ));
        }

        let cbor_data = ciborium_to_vec(&wrapped)?;
        // Append BLAKE3 keyed MAC using device key for integrity protection
        let device_key = crate::device::load_or_create_device_key(&self.base_dir)?;
        let mac = compute_identity_mac(&cbor_data, &device_key);
        let mut data = cbor_data;
        data.extend_from_slice(mac.as_bytes());
        crate::io::atomic_write(&path, &data)?;

        Ok(identity)
    }

    pub fn load(&self, fingerprint: &KeyFingerprint, passphrase: &str) -> Result<LoadedIdentity> {
        let path = self.identity_path(fingerprint);
        if !path.exists() {
            return Err(SigynError::IdentityNotFound(fingerprint.to_hex()));
        }

        let file_data = std::fs::read(&path)?;
        // Verify and strip MAC if present
        let data = self.verify_and_strip_mac(&path, &file_data)?;
        let wrapped: WrappedIdentity = ciborium_from_slice(&data)?;

        let enc_bytes = wrapped.unwrap_encryption_key(passphrase)?;
        let sign_bytes = wrapped.unwrap_signing_key(passphrase)?;

        let encryption_key = X25519PrivateKey::from_bytes(enc_bytes);
        let signing_key = SigningKeyPair::from_bytes(&sign_bytes);

        let identity = Identity {
            fingerprint: wrapped.fingerprint.clone(),
            profile: wrapped.profile,
            encryption_pubkey: wrapped.encryption_pubkey,
            signing_pubkey: wrapped.signing_pubkey,
        };

        Ok(LoadedIdentity::new(identity, encryption_key, signing_key))
    }

    pub fn list(&self) -> Result<Vec<Identity>> {
        let dir = self.identities_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut identities = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "identity") {
                let file_data = std::fs::read(&path)?;
                let data = self.verify_and_strip_mac(&path, &file_data)?;
                let wrapped: WrappedIdentity = ciborium_from_slice(&data)?;
                identities.push(Identity {
                    fingerprint: wrapped.fingerprint,
                    profile: wrapped.profile,
                    encryption_pubkey: wrapped.encryption_pubkey,
                    signing_pubkey: wrapped.signing_pubkey,
                });
            }
        }
        Ok(identities)
    }

    pub fn find_by_name(&self, name: &str) -> Result<Option<Identity>> {
        Ok(self.list()?.into_iter().find(|i| i.profile.name == name))
    }

    /// Verify and strip the BLAKE3 keyed MAC from identity file data.
    /// If the MAC is missing (old format), warn and rewrite the file with a MAC.
    fn verify_and_strip_mac(&self, path: &std::path::Path, file_data: &[u8]) -> Result<Vec<u8>> {
        let device_key = crate::device::load_or_create_device_key(&self.base_dir)?;

        // Try with MAC first (new format: cbor_data || mac[32])
        if file_data.len() > IDENTITY_MAC_LEN {
            let (cbor_data, mac_bytes) = file_data.split_at(file_data.len() - IDENTITY_MAC_LEN);
            let expected = compute_identity_mac(cbor_data, &device_key);
            if expected.as_bytes() == mac_bytes {
                return Ok(cbor_data.to_vec());
            }
        }

        // Try without MAC (old format) — verify it's valid CBOR
        let _: WrappedIdentity = ciborium_from_slice(file_data)?;

        // Migration: rewrite with MAC appended
        eprintln!(
            "warning: identity file {} missing integrity MAC — upgrading",
            path.display()
        );
        let mac = compute_identity_mac(file_data, &device_key);
        let mut new_data = file_data.to_vec();
        new_data.extend_from_slice(mac.as_bytes());
        let _ = crate::io::atomic_write(path, &new_data);

        Ok(file_data.to_vec())
    }
}

/// Compute a BLAKE3 keyed MAC for identity file integrity.
fn compute_identity_mac(data: &[u8], device_key: &[u8; 32]) -> blake3::Hash {
    let key = blake3::derive_key(IDENTITY_MAC_CONTEXT, device_key);
    blake3::keyed_hash(&key, data)
}

fn ciborium_to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| SigynError::CborEncode(e.to_string()))?;
    Ok(buf)
}

fn ciborium_from_slice<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T> {
    ciborium::from_reader(data).map_err(|e| SigynError::CborDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_load_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().to_path_buf());
        let profile = IdentityProfile::new("alice".into(), Some("alice@example.com".into()));

        let identity = store.generate(profile, "passphrase123").unwrap();
        assert!(!identity.fingerprint.to_hex().is_empty());

        let loaded = store.load(&identity.fingerprint, "passphrase123").unwrap();
        assert_eq!(loaded.identity.fingerprint, identity.fingerprint);
        assert_eq!(loaded.identity.profile.name, "alice");
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().to_path_buf());
        let profile = IdentityProfile::new("bob".into(), None);

        let identity = store.generate(profile, "correct").unwrap();
        assert!(store.load(&identity.fingerprint, "wrong").is_err());
    }

    #[test]
    fn test_list_identities() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().to_path_buf());

        store
            .generate(IdentityProfile::new("alice".into(), None), "pass1")
            .unwrap();
        store
            .generate(IdentityProfile::new("bob".into(), None), "pass2")
            .unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
    }
}
