use std::path::Path;

use sigyn_core::error::{Result, SigynError};
pub use sigyn_core::vault::env_file::*;

pub fn write_encrypted_env(path: &Path, env_file: &EncryptedEnvFile) -> Result<()> {
    let mut data = Vec::new();
    ciborium::into_writer(env_file, &mut data)
        .map_err(|e| SigynError::CborEncode(e.to_string()))?;
    crate::io::atomic_write(path, &data)
}

pub fn read_encrypted_env(path: &Path) -> Result<EncryptedEnvFile> {
    let data = std::fs::read(path)?;
    // Use a cursor to detect trailing bytes after CBOR deserialization.
    // Trailing bytes indicate the file was tampered with (appended data).
    let mut cursor = std::io::Cursor::new(&data);
    let env_file: EncryptedEnvFile =
        ciborium::from_reader(&mut cursor).map_err(|e| SigynError::CborDecode(e.to_string()))?;
    let consumed = cursor.position() as usize;
    if consumed != data.len() {
        return Err(SigynError::CborDecode(format!(
            "vault file has {} trailing bytes — file may be tampered",
            data.len() - consumed
        )));
    }
    Ok(env_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::crypto::vault_cipher::VaultCipher;
    use sigyn_core::secrets::types::SecretValue;

    #[test]
    fn test_write_read_encrypted_env_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");

        let cipher = VaultCipher::generate();
        let fp = sigyn_core::crypto::keys::KeyFingerprint([0u8; 16]);
        let mut env = PlaintextEnv::new();
        env.set(
            "DB_URL".into(),
            SecretValue::String("postgres://localhost".into()),
            &fp,
        );

        let encrypted = encrypt_env(&env, &cipher, "dev").unwrap();
        write_encrypted_env(&path, &encrypted).unwrap();

        let loaded = read_encrypted_env(&path).unwrap();
        let decrypted = decrypt_env(&loaded, &cipher).unwrap();
        assert_eq!(decrypted.entries.len(), 1);
    }
}
