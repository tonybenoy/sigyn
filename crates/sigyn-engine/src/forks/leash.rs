use crate::policy::storage::{VaultPolicy, VaultPolicyExt};
use crate::vault::{env_file, VaultManifest, VaultPaths};
use sigyn_core::crypto::envelope;
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::error::{Result, SigynError};
use sigyn_core::forks::types::*;
use std::collections::BTreeMap;

#[allow(clippy::too_many_arguments)]
pub fn create_leashed_fork(
    parent_paths: &VaultPaths,
    parent_name: &str,
    fork_name: &str,
    parent_cipher: &VaultCipher,
    parent_env_ciphers: &BTreeMap<String, VaultCipher>,
    parent_manifest: &VaultManifest,
    fork_owner_pubkey: &sigyn_core::crypto::X25519PublicKey,
    parent_admin_pubkey: &sigyn_core::crypto::X25519PublicKey,
    creator: &KeyFingerprint,
) -> Result<Fork> {
    let fork_paths = parent_paths;

    // Create fork directory structure
    let fork_dir = fork_paths.vault_dir(fork_name);
    if fork_dir.exists() {
        return Err(SigynError::VaultAlreadyExists(fork_name.into()));
    }
    std::fs::create_dir_all(fork_paths.env_dir(fork_name))?;

    // Generate independent vault key and per-env keys for the fork
    let fork_vault_cipher = VaultCipher::generate();
    let fork_recipients = &[fork_owner_pubkey.clone(), parent_admin_pubkey.clone()];

    let mut fork_env_keys = BTreeMap::new();
    let mut fork_env_recipients = BTreeMap::new();
    for env_name in &parent_manifest.environments {
        let env_cipher = VaultCipher::generate();
        fork_env_keys.insert(env_name.clone(), *env_cipher.key_bytes());
        fork_env_recipients.insert(env_name.clone(), fork_recipients.to_vec());
    }

    let fork_vault_id = uuid::Uuid::new_v4();
    let header = envelope::seal_v2(
        fork_vault_cipher.key_bytes(),
        &fork_env_keys,
        fork_recipients,
        &fork_env_recipients,
        fork_vault_id,
    )?;

    // Create fork manifest
    let mut fork_manifest = VaultManifest::new(fork_name.into(), creator.clone());
    fork_manifest.environments = parent_manifest.environments.clone();

    // Write sealed manifest and signed header
    let sealed_manifest = fork_manifest
        .to_sealed_bytes(&fork_vault_cipher)
        .map_err(|e| SigynError::Serialization(e.to_string()))?;
    std::fs::write(fork_paths.manifest_path(fork_name), sealed_manifest)?;
    let mut header_bytes = Vec::new();
    ciborium::into_writer(&header, &mut header_bytes)
        .map_err(|e| SigynError::CborEncode(e.to_string()))?;
    std::fs::write(fork_paths.members_path(fork_name), header_bytes)?;

    // Copy encrypted envs, re-encrypting with fork's per-env keys
    for env_name in &parent_manifest.environments {
        let parent_env_path = parent_paths.env_path(parent_name, env_name);
        if parent_env_path.exists() {
            let parent_env_cipher = parent_env_ciphers.get(env_name).unwrap_or(parent_cipher);
            let encrypted = env_file::read_encrypted_env(&parent_env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, parent_env_cipher)?;
            let fork_env_cipher = VaultCipher::new(
                *fork_env_keys
                    .get(env_name)
                    .unwrap_or(fork_vault_cipher.key_bytes()),
            );
            let fork_encrypted = env_file::encrypt_env(&plaintext, &fork_env_cipher, env_name)?;
            env_file::write_encrypted_env(
                &fork_paths.env_path(fork_name, env_name),
                &fork_encrypted,
            )?;
        }
    }

    // Initialize empty policy for fork
    let policy = VaultPolicy::new();
    policy.save_encrypted(&fork_paths.policy_path(fork_name), &fork_vault_cipher)?;

    let fork = Fork {
        id: uuid::Uuid::new_v4(),
        parent_vault_id: parent_manifest.vault_id,
        fork_vault_id: fork_manifest.vault_id,
        mode: ForkMode::Leashed,
        status: ForkStatus::Active,
        policy: ForkPolicy {
            sharing: ForkSharingPolicy::SharedWithParent,
            max_drift_days: Some(30),
            inherit_revocations: true,
            allow_new_members: false,
        },
        created_by: creator.clone(),
        created_at: chrono::Utc::now(),
        expires_at: None,
    };

    Ok(fork)
}

#[allow(clippy::too_many_arguments)]
pub fn create_unleashed_fork(
    parent_paths: &VaultPaths,
    parent_name: &str,
    fork_name: &str,
    parent_cipher: &VaultCipher,
    parent_env_ciphers: &BTreeMap<String, VaultCipher>,
    parent_manifest: &VaultManifest,
    fork_owner_pubkey: &sigyn_core::crypto::X25519PublicKey,
    creator: &KeyFingerprint,
) -> Result<Fork> {
    let fork_paths = parent_paths;
    let fork_dir = fork_paths.vault_dir(fork_name);
    if fork_dir.exists() {
        return Err(SigynError::VaultAlreadyExists(fork_name.into()));
    }
    std::fs::create_dir_all(fork_paths.env_dir(fork_name))?;

    // Completely independent vault key + per-env keys — no parent access
    let fork_vault_cipher = VaultCipher::generate();
    let fork_recipients = std::slice::from_ref(fork_owner_pubkey);

    let mut fork_env_keys = BTreeMap::new();
    let mut fork_env_recipients = BTreeMap::new();
    for env_name in &parent_manifest.environments {
        let env_cipher = VaultCipher::generate();
        fork_env_keys.insert(env_name.clone(), *env_cipher.key_bytes());
        fork_env_recipients.insert(env_name.clone(), fork_recipients.to_vec());
    }

    let fork_vault_id = uuid::Uuid::new_v4();
    let header = envelope::seal_v2(
        fork_vault_cipher.key_bytes(),
        &fork_env_keys,
        fork_recipients,
        &fork_env_recipients,
        fork_vault_id,
    )?;

    let mut fork_manifest = VaultManifest::new(fork_name.into(), creator.clone());
    fork_manifest.environments = parent_manifest.environments.clone();

    let sealed_manifest = fork_manifest
        .to_sealed_bytes(&fork_vault_cipher)
        .map_err(|e| SigynError::Serialization(e.to_string()))?;
    std::fs::write(fork_paths.manifest_path(fork_name), sealed_manifest)?;
    let mut header_bytes = Vec::new();
    ciborium::into_writer(&header, &mut header_bytes)
        .map_err(|e| SigynError::CborEncode(e.to_string()))?;
    std::fs::write(fork_paths.members_path(fork_name), header_bytes)?;

    for env_name in &parent_manifest.environments {
        let parent_env_path = parent_paths.env_path(parent_name, env_name);
        if parent_env_path.exists() {
            let parent_env_cipher = parent_env_ciphers.get(env_name).unwrap_or(parent_cipher);
            let encrypted = env_file::read_encrypted_env(&parent_env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, parent_env_cipher)?;
            let fork_env_cipher = VaultCipher::new(
                *fork_env_keys
                    .get(env_name)
                    .unwrap_or(fork_vault_cipher.key_bytes()),
            );
            let fork_encrypted = env_file::encrypt_env(&plaintext, &fork_env_cipher, env_name)?;
            env_file::write_encrypted_env(
                &fork_paths.env_path(fork_name, env_name),
                &fork_encrypted,
            )?;
        }
    }

    let policy = VaultPolicy::new();
    policy.save_encrypted(&fork_paths.policy_path(fork_name), &fork_vault_cipher)?;

    let fork = Fork {
        id: uuid::Uuid::new_v4(),
        parent_vault_id: parent_manifest.vault_id,
        fork_vault_id: fork_manifest.vault_id,
        mode: ForkMode::Unleashed,
        status: ForkStatus::Active,
        policy: ForkPolicy {
            sharing: ForkSharingPolicy::Private,
            max_drift_days: None,
            inherit_revocations: false,
            allow_new_members: true,
        },
        created_by: creator.clone(),
        created_at: chrono::Utc::now(),
        expires_at: None,
    };

    Ok(fork)
}
