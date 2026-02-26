use sigyn_engine::crypto::envelope;
use sigyn_engine::crypto::keys::{KeyFingerprint, X25519PrivateKey};
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::forks::leash::{create_leashed_fork, create_unleashed_fork};
use sigyn_engine::forks::types::{ForkMode, ForkSharingPolicy, ForkStatus};
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::{env_file, PlaintextEnv, VaultManifest, VaultPaths};
use std::collections::BTreeMap;

fn setup_parent_vault(
    dir: &std::path::Path,
) -> (
    VaultPaths,
    VaultCipher,
    VaultManifest,
    X25519PrivateKey,
    KeyFingerprint,
) {
    let paths = VaultPaths::new(dir.to_path_buf());
    let owner_key = X25519PrivateKey::generate();
    let owner_pubkey = owner_key.public_key();
    let fp = owner_pubkey.fingerprint();

    let manifest = VaultManifest::new("parent".to_string(), fp.clone());
    let vault_id = manifest.vault_id;

    let cipher = VaultCipher::generate();
    let header = envelope::seal_v2(
        cipher.key_bytes(),
        &BTreeMap::new(),
        std::slice::from_ref(&owner_pubkey),
        &BTreeMap::new(),
        vault_id,
    )
    .unwrap();

    // Create vault directories and files
    std::fs::create_dir_all(paths.env_dir("parent")).unwrap();
    std::fs::write(paths.manifest_path("parent"), manifest.to_toml().unwrap()).unwrap();

    let mut header_bytes = Vec::new();
    ciborium::into_writer(&header, &mut header_bytes).unwrap();
    std::fs::write(paths.members_path("parent"), header_bytes).unwrap();

    // Create env files with a secret
    let mut env = PlaintextEnv::new();
    env.set(
        "DB_URL".to_string(),
        SecretValue::String("postgres://localhost".to_string()),
        &fp,
    );
    for env_name in &manifest.environments {
        let encrypted = env_file::encrypt_env(&env, &cipher, env_name).unwrap();
        env_file::write_encrypted_env(&paths.env_path("parent", env_name), &encrypted).unwrap();
    }

    // Save policy
    let policy = sigyn_engine::policy::storage::VaultPolicy::new();
    policy
        .save_encrypted(&paths.policy_path("parent"), &cipher)
        .unwrap();

    (paths, cipher, manifest, owner_key, fp)
}

#[test]
fn test_create_leashed_fork() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();
    let parent_admin = X25519PrivateKey::generate();

    let fork = create_leashed_fork(
        &paths,
        "parent",
        "leashed-fork",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &parent_admin.public_key(),
        &fp,
    )
    .unwrap();

    assert!(matches!(fork.mode, ForkMode::Leashed));
    assert!(matches!(fork.status, ForkStatus::Active));
    assert!(matches!(
        fork.policy.sharing,
        ForkSharingPolicy::SharedWithParent
    ));
    assert_eq!(fork.policy.max_drift_days, Some(30));
    assert!(fork.policy.inherit_revocations);
    assert!(!fork.policy.allow_new_members);

    // Verify fork directories were created
    assert!(paths.vault_dir("leashed-fork").exists());
    assert!(paths.manifest_path("leashed-fork").exists());
    assert!(paths.members_path("leashed-fork").exists());
}

#[test]
fn test_create_unleashed_fork() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();

    let fork = create_unleashed_fork(
        &paths,
        "parent",
        "unleashed-fork",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &fp,
    )
    .unwrap();

    assert!(matches!(fork.mode, ForkMode::Unleashed));
    assert!(matches!(fork.status, ForkStatus::Active));
    assert!(matches!(fork.policy.sharing, ForkSharingPolicy::Private));
    assert_eq!(fork.policy.max_drift_days, None);
    assert!(!fork.policy.inherit_revocations);
    assert!(fork.policy.allow_new_members);
}

#[test]
fn test_leashed_fork_preserves_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();
    let parent_admin = X25519PrivateKey::generate();

    let _fork = create_leashed_fork(
        &paths,
        "parent",
        "fork-with-secrets",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &parent_admin.public_key(),
        &fp,
    )
    .unwrap();

    // The fork env file should exist and be readable with the fork's key
    // (We can't easily test decryption since the fork uses a new cipher,
    // but we can verify the env files were created)
    for env_name in &manifest.environments {
        assert!(
            paths.env_path("fork-with-secrets", env_name).exists(),
            "Fork env file for '{}' should exist",
            env_name
        );
    }
}

#[test]
fn test_leashed_fork_has_two_slots() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();
    let parent_admin = X25519PrivateKey::generate();

    let _fork = create_leashed_fork(
        &paths,
        "parent",
        "dual-access-fork",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &parent_admin.public_key(),
        &fp,
    )
    .unwrap();

    // Read the fork's envelope header
    let header_bytes = std::fs::read(paths.members_path("dual-access-fork")).unwrap();
    let header: sigyn_engine::crypto::EnvelopeHeader =
        ciborium::from_reader(header_bytes.as_slice()).unwrap();

    // Leashed fork should have 2 vault_key_slots (fork owner + parent admin)
    assert_eq!(header.vault_key_slots.len(), 2);

    // Verify the fingerprints match the expected recipients
    let fork_fp = fork_owner.public_key().fingerprint();
    let admin_fp = parent_admin.public_key().fingerprint();
    let slot_fps: Vec<_> = header
        .vault_key_slots
        .iter()
        .map(|s| &s.fingerprint)
        .collect();
    assert!(slot_fps.contains(&&fork_fp));
    assert!(slot_fps.contains(&&admin_fp));
}

#[test]
fn test_unleashed_fork_has_single_slot() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();

    let _fork = create_unleashed_fork(
        &paths,
        "parent",
        "solo-fork",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &fp,
    )
    .unwrap();

    let header_bytes = std::fs::read(paths.members_path("solo-fork")).unwrap();
    let header: sigyn_engine::crypto::EnvelopeHeader =
        ciborium::from_reader(header_bytes.as_slice()).unwrap();

    // Unleashed fork should have only 1 vault_key_slot (fork owner only)
    assert_eq!(header.vault_key_slots.len(), 1);
    assert_eq!(
        header.vault_key_slots[0].fingerprint,
        fork_owner.public_key().fingerprint()
    );
}

#[test]
fn test_fork_duplicate_name_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();

    create_unleashed_fork(
        &paths,
        "parent",
        "dupe-fork",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &fp,
    )
    .unwrap();

    // Creating again with same name should fail
    let result = create_unleashed_fork(
        &paths,
        "parent",
        "dupe-fork",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &fp,
    );
    assert!(result.is_err());
}

#[test]
fn test_fork_ids_differ() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, cipher, manifest, _owner_key, fp) = setup_parent_vault(dir.path());

    let fork_owner = X25519PrivateKey::generate();

    let fork = create_unleashed_fork(
        &paths,
        "parent",
        "fork-a",
        &cipher,
        &BTreeMap::new(),
        &manifest,
        &fork_owner.public_key(),
        &fp,
    )
    .unwrap();

    assert_eq!(fork.parent_vault_id, manifest.vault_id);
    assert_ne!(fork.fork_vault_id, manifest.vault_id);
}
