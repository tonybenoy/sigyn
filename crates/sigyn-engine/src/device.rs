use std::path::Path;

use sigyn_core::error::{Result, SigynError};

const DEVICE_KEY_FILE: &str = ".device_key";
const DEVICE_KEY_LEN: usize = 32;
/// New format: key(32) || blake3(key || context)(32) = 64 bytes
const DEVICE_KEY_WITH_HASH_LEN: usize = 64;
const DEVICE_KEY_HASH_CONTEXT: &[u8] = b"sigyn-device-key-v1";

/// Load the device key from `sigyn_home/.device_key`, creating it if it doesn't exist.
///
/// The device key is a 32-byte random value used to encrypt Tier A files
/// (config, context, notifications) that must be readable before any identity
/// is loaded. It is stored with mode 0o400 (read-only by owner).
/// Compute the integrity hash for the device key: BLAKE3(key || context).
fn device_key_hash(key: &[u8; DEVICE_KEY_LEN]) -> [u8; 32] {
    let mut input = Vec::with_capacity(DEVICE_KEY_LEN + DEVICE_KEY_HASH_CONTEXT.len());
    input.extend_from_slice(key);
    input.extend_from_slice(DEVICE_KEY_HASH_CONTEXT);
    *blake3::hash(&input).as_bytes()
}

pub fn load_or_create_device_key(sigyn_home: &Path) -> Result<[u8; DEVICE_KEY_LEN]> {
    let path = sigyn_home.join(DEVICE_KEY_FILE);
    if path.exists() {
        let data = std::fs::read(&path)?;
        if data.len() == DEVICE_KEY_WITH_HASH_LEN {
            // New format: key(32) || hash(32)
            let mut key = [0u8; DEVICE_KEY_LEN];
            key.copy_from_slice(&data[..DEVICE_KEY_LEN]);
            let stored_hash = &data[DEVICE_KEY_LEN..];
            let expected_hash = device_key_hash(&key);
            if stored_hash != expected_hash {
                return Err(SigynError::InvalidKey(
                    "device key integrity check failed — file may be tampered".into(),
                ));
            }
            Ok(key)
        } else if data.len() == DEVICE_KEY_LEN {
            // Old format: key only — upgrade to new format
            let mut key = [0u8; DEVICE_KEY_LEN];
            key.copy_from_slice(&data);
            let hash = device_key_hash(&key);
            let mut new_data = Vec::with_capacity(DEVICE_KEY_WITH_HASH_LEN);
            new_data.extend_from_slice(&key);
            new_data.extend_from_slice(&hash);
            // Need write permission temporarily for upgrade
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            crate::io::atomic_write(&path, &new_data)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
            }
            Ok(key)
        } else {
            Err(SigynError::InvalidKey(format!(
                "device key has wrong length: {} (expected {} or {})",
                data.len(),
                DEVICE_KEY_LEN,
                DEVICE_KEY_WITH_HASH_LEN
            )))
        }
    } else {
        let mut key = [0u8; DEVICE_KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let hash = device_key_hash(&key);

        let mut data = Vec::with_capacity(DEVICE_KEY_WITH_HASH_LEN);
        data.extend_from_slice(&key);
        data.extend_from_slice(&hash);

        std::fs::create_dir_all(sigyn_home)?;
        crate::io::atomic_write(&path, &data)?;

        // Set 0o400 (read-only by owner) for extra protection
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        }

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let key1 = load_or_create_device_key(tmp.path()).unwrap();
        let key2 = load_or_create_device_key(tmp.path()).unwrap();
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]);
    }

    #[test]
    fn test_wrong_length_device_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(DEVICE_KEY_FILE);
        std::fs::write(&path, b"too short").unwrap();
        assert!(load_or_create_device_key(tmp.path()).is_err());
    }
}
