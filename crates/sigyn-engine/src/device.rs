use std::path::Path;

use sigyn_core::error::{Result, SigynError};

const DEVICE_KEY_FILE: &str = ".device_key";
const DEVICE_KEY_LEN: usize = 32;

/// Load the device key from `sigyn_home/.device_key`, creating it if it doesn't exist.
///
/// The device key is a 32-byte random value used to encrypt Tier A files
/// (config, context, notifications) that must be readable before any identity
/// is loaded. It is stored with mode 0o400 (read-only by owner).
pub fn load_or_create_device_key(sigyn_home: &Path) -> Result<[u8; DEVICE_KEY_LEN]> {
    let path = sigyn_home.join(DEVICE_KEY_FILE);
    if path.exists() {
        let data = std::fs::read(&path)?;
        if data.len() != DEVICE_KEY_LEN {
            return Err(SigynError::InvalidKey(format!(
                "device key has wrong length: {} (expected {})",
                data.len(),
                DEVICE_KEY_LEN
            )));
        }
        let mut key = [0u8; DEVICE_KEY_LEN];
        key.copy_from_slice(&data);
        Ok(key)
    } else {
        let mut key = [0u8; DEVICE_KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);

        std::fs::create_dir_all(sigyn_home)?;
        crate::io::atomic_write(&path, &key)?;

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
