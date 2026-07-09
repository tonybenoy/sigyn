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

    /// Change the passphrase for an existing identity.
    ///
    /// Loads the identity with the old passphrase, re-wraps the keys with the
    /// new passphrase (generating a fresh salt), and atomically overwrites the file.
    pub fn change_passphrase(
        &self,
        fingerprint: &KeyFingerprint,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<()> {
        let path = self.identity_path(fingerprint);
        if !path.exists() {
            return Err(SigynError::IdentityNotFound(fingerprint.to_hex()));
        }

        // Load and verify with old passphrase
        let file_data = std::fs::read(&path)?;
        let data = self.verify_and_strip_mac(&path, &file_data)?;
        let wrapped: WrappedIdentity = ciborium_from_slice(&data)?;

        let mut enc_bytes = wrapped.unwrap_encryption_key(old_passphrase)?;
        let mut sign_bytes = wrapped.unwrap_signing_key(old_passphrase)?;

        // Re-wrap with new passphrase (generates new salt)
        let result = WrappedIdentity::wrap(
            &enc_bytes,
            &sign_bytes,
            wrapped.encryption_pubkey,
            wrapped.signing_pubkey,
            wrapped.profile,
            new_passphrase,
        );

        // Zeroize raw key bytes regardless of wrap outcome
        enc_bytes.iter_mut().for_each(|b| *b = 0);
        sign_bytes.iter_mut().for_each(|b| *b = 0);

        let new_wrapped = result?;

        // Serialize and write with MAC
        let cbor_data = ciborium_to_vec(&new_wrapped)?;
        let device_key = crate::device::load_or_create_device_key(&self.base_dir)?;
        let mac = compute_identity_mac(&cbor_data, &device_key);
        let mut new_data = cbor_data;
        new_data.extend_from_slice(mac.as_bytes());
        crate::io::atomic_write(&path, &new_data)?;

        Ok(())
    }

    /// Delete an identity file from disk.
    pub fn delete(&self, fingerprint: &KeyFingerprint) -> Result<()> {
        let path = self.identity_path(fingerprint);
        if !path.exists() {
            return Err(SigynError::IdentityNotFound(fingerprint.to_hex()));
        }
        std::fs::remove_file(&path)?;
        Ok(())
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

        // Try without MAC (old format). The old format is a bare CBOR
        // WrappedIdentity with NO trailing bytes, so require the deserializer
        // to consume the entire file: ciborium ignores trailing data, and a
        // new-format blob with a corrupted/forged MAC would otherwise parse
        // "successfully" here and silently bypass the integrity check.
        let mut cursor = std::io::Cursor::new(file_data);
        let parsed: std::result::Result<WrappedIdentity, _> = ciborium::from_reader(&mut cursor);
        let fully_consumed = cursor.position() as usize == file_data.len();
        if parsed.is_err() || !fully_consumed {
            return Err(SigynError::Deserialization(format!(
                "identity file {} failed integrity verification (MAC mismatch or corrupted data)",
                path.display()
            )));
        }

        // Migration: rewrite with MAC appended. Failure to upgrade is not
        // fatal (e.g. read-only filesystem) but must not pass silently.
        eprintln!(
            "warning: identity file {} missing integrity MAC — upgrading",
            path.display()
        );
        let mac = compute_identity_mac(file_data, &device_key);
        let mut new_data = file_data.to_vec();
        new_data.extend_from_slice(mac.as_bytes());
        if let Err(e) = crate::io::atomic_write(path, &new_data) {
            eprintln!(
                "warning: failed to upgrade identity file {} with integrity MAC: {}",
                path.display(),
                e
            );
        }

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
    fn test_corrupted_mac_is_rejected_not_treated_as_old_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().to_path_buf());
        let profile = IdentityProfile::new("carol".into(), None);

        let identity = store.generate(profile, "pass").unwrap();
        let path = store.identity_path(&identity.fingerprint);

        // Craft a new-format blob (cbor || mac) with a corrupted MAC. The
        // loader must ERROR — not fall back to parsing the CBOR prefix as
        // "old format" (ciborium ignores trailing bytes).
        let mut data = std::fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        // Can't unwrap_err (LoadedIdentity has no Debug — key material); match.
        match store.load(&identity.fingerprint, "pass") {
            Ok(_) => panic!("corrupted MAC must be rejected"),
            Err(e) => assert!(
                e.to_string().contains("integrity verification"),
                "error should indicate an integrity failure, got: {}",
                e
            ),
        }
        assert!(store.list().is_err(), "list must also reject corrupted MAC");
    }

    #[test]
    fn test_corrupted_cbor_with_valid_length_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().to_path_buf());
        let profile = IdentityProfile::new("dave".into(), None);

        let identity = store.generate(profile, "pass").unwrap();
        let path = store.identity_path(&identity.fingerprint);

        // Corrupt a byte inside the CBOR payload (MAC now mismatches, and the
        // fallback old-format parse must not accept it either).
        let mut data = std::fs::read(&path).unwrap();
        data[10] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        assert!(store.load(&identity.fingerprint, "pass").is_err());
    }

    #[test]
    fn test_genuine_old_format_still_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().to_path_buf());
        let profile = IdentityProfile::new("erin".into(), None);

        let identity = store.generate(profile, "pass").unwrap();
        let path = store.identity_path(&identity.fingerprint);

        // Strip the MAC to simulate a pre-MAC (old format) identity file.
        let data = std::fs::read(&path).unwrap();
        let cbor_only = &data[..data.len() - IDENTITY_MAC_LEN];
        std::fs::write(&path, cbor_only).unwrap();

        // Old format loads and is migrated (MAC re-appended on disk).
        let loaded = store.load(&identity.fingerprint, "pass").unwrap();
        assert_eq!(loaded.identity.profile.name, "erin");
        let migrated = std::fs::read(&path).unwrap();
        assert_eq!(
            migrated.len(),
            cbor_only.len() + IDENTITY_MAC_LEN,
            "migration should re-append the MAC"
        );

        // And the migrated file loads through the MAC-verified path.
        store.load(&identity.fingerprint, "pass").unwrap();
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
