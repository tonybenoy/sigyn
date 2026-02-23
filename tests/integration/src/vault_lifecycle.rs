use sigyn_core::crypto::envelope::{seal_master_key, unseal_master_key};
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::identity::keygen::IdentityStore;
use sigyn_core::identity::profile::IdentityProfile;
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::env_file::{
    decrypt_env, encrypt_env, read_encrypted_env, write_encrypted_env, PlaintextEnv,
};
use sigyn_core::vault::manifest::VaultManifest;
use tempfile::TempDir;

#[test]
fn test_full_vault_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // 1. Generate an identity
    let store = IdentityStore::new(tmp.path().to_path_buf());
    let profile = IdentityProfile::new("owner".into(), Some("owner@example.com".into()));
    let identity = store.generate(profile, "test-passphrase").unwrap();
    let loaded = store
        .load(&identity.fingerprint, "test-passphrase")
        .unwrap();

    // 2. Create a vault manifest
    let manifest = VaultManifest::new("my-vault".into(), identity.fingerprint.clone());
    let vault_id = manifest.vault_id;
    assert_eq!(manifest.name, "my-vault");
    assert_eq!(manifest.environments.len(), 3);

    // Write manifest to disk
    let manifest_toml = manifest.to_toml().unwrap();
    std::fs::write(vault_dir.join("manifest.toml"), &manifest_toml).unwrap();

    // 3. Seal a master key for the owner
    let master_key: [u8; 32] = rand_key();
    let header = seal_master_key(
        &master_key,
        &[loaded.identity.encryption_pubkey.clone()],
        vault_id,
    )
    .unwrap();

    // Verify the owner can unseal
    let recovered = unseal_master_key(&header, loaded.encryption_key(), vault_id).unwrap();
    assert_eq!(master_key, recovered);

    // 4. Create a cipher from the master key and set a secret
    let cipher = VaultCipher::new(master_key);
    let fp = identity.fingerprint.clone();
    let mut env = PlaintextEnv::new();
    env.set(
        "DATABASE_URL".into(),
        SecretValue::String("postgres://localhost:5432/mydb".into()),
        &fp,
    );

    // 5. Encrypt and write to disk
    let encrypted = encrypt_env(&env, &cipher, "dev").unwrap();
    let env_path = vault_dir.join("dev.env");
    write_encrypted_env(&env_path, &encrypted).unwrap();

    // 6. Read back and decrypt - verify the value matches
    let read_back = read_encrypted_env(&env_path).unwrap();
    let decrypted = decrypt_env(&read_back, &cipher).unwrap();
    assert_eq!(decrypted.len(), 1);
    assert_eq!(
        decrypted.get("DATABASE_URL").unwrap().value,
        SecretValue::String("postgres://localhost:5432/mydb".into())
    );

    // 7. Update the secret
    let mut env2 = decrypted;
    env2.set(
        "DATABASE_URL".into(),
        SecretValue::String("postgres://prod-host:5432/mydb".into()),
        &fp,
    );
    assert_eq!(env2.get("DATABASE_URL").unwrap().metadata.version, 2);

    let encrypted2 = encrypt_env(&env2, &cipher, "dev").unwrap();
    write_encrypted_env(&env_path, &encrypted2).unwrap();

    // Verify updated value
    let read_back2 = read_encrypted_env(&env_path).unwrap();
    let decrypted2 = decrypt_env(&read_back2, &cipher).unwrap();
    assert_eq!(
        decrypted2.get("DATABASE_URL").unwrap().value,
        SecretValue::String("postgres://prod-host:5432/mydb".into())
    );

    // 8. Delete the secret
    let mut env3 = decrypted2;
    let removed = env3.remove("DATABASE_URL");
    assert!(removed.is_some());
    assert!(env3.is_empty());

    // Encrypt and write the now-empty env
    let encrypted3 = encrypt_env(&env3, &cipher, "dev").unwrap();
    write_encrypted_env(&env_path, &encrypted3).unwrap();

    // Verify it is gone
    let read_back3 = read_encrypted_env(&env_path).unwrap();
    let decrypted3 = decrypt_env(&read_back3, &cipher).unwrap();
    assert!(decrypted3.is_empty());
    assert!(decrypted3.get("DATABASE_URL").is_none());
}

#[test]
fn test_manifest_roundtrip_via_toml() {
    let fp = KeyFingerprint([0xAA; 16]);
    let manifest = VaultManifest::new("roundtrip-vault".into(), fp);
    let toml_str = manifest.to_toml().unwrap();
    let parsed = VaultManifest::from_toml(&toml_str).unwrap();
    assert_eq!(parsed.vault_id, manifest.vault_id);
    assert_eq!(parsed.name, "roundtrip-vault");
    assert_eq!(parsed.environments, manifest.environments);
}

fn rand_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}
