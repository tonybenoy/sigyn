use std::path::Path;

use uuid::Uuid;

use super::manifest::NodeManifest;
use super::path::{HierarchyPaths, OrgPath};
use crate::crypto::envelope::{self, EnvelopeHeader};
use crate::crypto::keys::{
    KeyFingerprint, SigningKeyPair, VerifyingKeyWrapper, X25519PrivateKey, X25519PublicKey,
};
use crate::crypto::vault_cipher::VaultCipher;
use crate::error::{Result, SigynError};
use crate::policy::storage::{VaultPolicy, VaultPolicyExt};
use crate::vault::VaultPaths;

/// Read an envelope header from a signed (SGSN) file.
/// If the file doesn't exist, returns a default empty header.
/// Verifies the signature when a verifying key and domain_id are provided.
fn read_header(
    path: &Path,
    verifying_key: Option<&VerifyingKeyWrapper>,
    domain_id: Option<Uuid>,
) -> Result<EnvelopeHeader> {
    if !path.exists() {
        return Ok(EnvelopeHeader::default());
    }
    let data = std::fs::read(path)?;
    // Try signed format first
    if crate::crypto::sealed::is_signed(&data) {
        if let (Some(vk), Some(did)) = (verifying_key, domain_id) {
            return envelope::verify_and_load_header(&data, did, vk);
        }
        // No key available — extract but warn
        return envelope::extract_header_unverified(&data);
    }
    // Fallback: legacy raw CBOR (pre-signing migration)
    ciborium::from_reader(data.as_slice()).map_err(|e| SigynError::CborDecode(e.to_string()))
}

/// Write an envelope header as a signed (SGSN) file.
fn write_header(
    path: &Path,
    header: &EnvelopeHeader,
    signing_key: &SigningKeyPair,
    domain_id: Uuid,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let signed = envelope::sign_header(header, signing_key, domain_id)?;
    std::fs::write(path, signed)?;
    Ok(())
}

/// Add a recipient slot to a single node's envelope.
fn add_recipient_to_node(
    members_path: &Path,
    master_key: &[u8; 32],
    new_pubkey: &X25519PublicKey,
    domain_id: Uuid,
    signing_key: &SigningKeyPair,
    verifying_key: Option<&VerifyingKeyWrapper>,
) -> Result<()> {
    let mut header = read_header(members_path, verifying_key, Some(domain_id))?;

    if header.version >= 2 {
        // V2: add vault_key_slot (env slots are managed by the vault, not the hierarchy)
        envelope::add_vault_key_recipient(&mut header, master_key, new_pubkey, domain_id)?;
    } else {
        // V1: single master key slot
        let new_fp = new_pubkey.fingerprint();
        if header.slots.iter().any(|s| s.fingerprint == new_fp) {
            return Ok(()); // Already has a slot
        }
        envelope::add_recipient(&mut header, master_key, new_pubkey, domain_id)?;
    }
    write_header(members_path, &header, signing_key, domain_id)?;
    Ok(())
}

/// Walk the subtree under `org_path` and add a recipient slot to every descendant node's
/// envelope. The actor must have access at each level to unseal and re-seal.
///
/// This also adds the recipient to all vaults linked to nodes in the subtree.
pub fn cascade_add_recipient(
    hierarchy_paths: &HierarchyPaths,
    vault_paths: &VaultPaths,
    org_path: &OrgPath,
    actor_private_key: &X25519PrivateKey,
    new_pubkey: &X25519PublicKey,
    signing_key: &SigningKeyPair,
) -> Result<Vec<String>> {
    let mut affected = Vec::new();

    add_recipient_to_subtree(
        hierarchy_paths,
        vault_paths,
        org_path,
        actor_private_key,
        new_pubkey,
        signing_key,
        &mut affected,
    )?;

    Ok(affected)
}

fn add_recipient_to_subtree(
    hierarchy_paths: &HierarchyPaths,
    vault_paths: &VaultPaths,
    path: &OrgPath,
    actor_private_key: &X25519PrivateKey,
    new_pubkey: &X25519PublicKey,
    signing_key: &SigningKeyPair,
    affected: &mut Vec<String>,
) -> Result<()> {
    let members_path = hierarchy_paths.members_path(path);
    let manifest_path = hierarchy_paths.manifest_path(path);

    if manifest_path.exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest = NodeManifest::from_toml(&manifest_content)?;

        // Unseal the node's master key using actor's private key
        let header = read_header(&members_path, None, Some(manifest.node_id))?;
        let master_key = envelope::unseal_master_key(&header, actor_private_key, manifest.node_id)?;

        // Add recipient to this node
        add_recipient_to_node(
            &members_path,
            &master_key,
            new_pubkey,
            manifest.node_id,
            signing_key,
            None,
        )?;
        affected.push(format!("node:{}", path));
    }

    // Process linked vaults
    let org_str = path.as_str();
    let vaults = vault_paths.list_vaults_for_org(&org_str, None)?;
    for vault_name in vaults {
        let vault_manifest_path = vault_paths.manifest_path(&vault_name);
        if let Ok(content) = std::fs::read_to_string(&vault_manifest_path) {
            if let Ok(vault_manifest) = crate::vault::VaultManifest::from_toml(&content) {
                if vault_manifest.org_path.as_deref() == Some(&org_str) {
                    let vault_members = vault_paths.members_path(&vault_name);
                    let vault_header =
                        read_header(&vault_members, None, Some(vault_manifest.vault_id))?;
                    let vault_mk = envelope::unseal_master_key(
                        &vault_header,
                        actor_private_key,
                        vault_manifest.vault_id,
                    )?;
                    add_recipient_to_node(
                        &vault_members,
                        &vault_mk,
                        new_pubkey,
                        vault_manifest.vault_id,
                        signing_key,
                        None,
                    )?;
                    affected.push(format!("vault:{}", vault_name));
                }
            }
        }
    }

    // Recurse into children
    let children = hierarchy_paths.list_children(path)?;
    for child_name in children {
        let child_path = path.child(&child_name)?;
        add_recipient_to_subtree(
            hierarchy_paths,
            vault_paths,
            &child_path,
            actor_private_key,
            new_pubkey,
            signing_key,
            affected,
        )?;
    }

    Ok(())
}

/// Remove a recipient slot from all descendant nodes and vaults in the subtree,
/// rotating master keys at each level to prevent the removed member from decrypting
/// future data.
///
/// Returns the list of affected node/vault paths.
pub fn cascade_remove_recipient(
    hierarchy_paths: &HierarchyPaths,
    vault_paths: &VaultPaths,
    org_path: &OrgPath,
    fingerprint: &KeyFingerprint,
    actor_private_key: &X25519PrivateKey,
    remaining_pubkeys: &[(KeyFingerprint, X25519PublicKey)],
    signing_key: &SigningKeyPair,
) -> Result<Vec<String>> {
    let mut affected = Vec::new();

    remove_recipient_from_subtree(
        hierarchy_paths,
        vault_paths,
        org_path,
        fingerprint,
        actor_private_key,
        remaining_pubkeys,
        signing_key,
        &mut affected,
    )?;

    Ok(affected)
}

#[allow(clippy::too_many_arguments)]
fn remove_recipient_from_subtree(
    hierarchy_paths: &HierarchyPaths,
    vault_paths: &VaultPaths,
    path: &OrgPath,
    fingerprint: &KeyFingerprint,
    actor_private_key: &X25519PrivateKey,
    remaining_pubkeys: &[(KeyFingerprint, X25519PublicKey)],
    signing_key: &SigningKeyPair,
    affected: &mut Vec<String>,
) -> Result<()> {
    let members_path = hierarchy_paths.members_path(path);
    let manifest_path = hierarchy_paths.manifest_path(path);
    let policy_path = hierarchy_paths.policy_path(path);

    if manifest_path.exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest = NodeManifest::from_toml(&manifest_content)?;

        let mut header = read_header(&members_path, None, Some(manifest.node_id))?;

        // Check if the target has a slot here (v1 or v2)
        let has_slot = if header.version >= 2 {
            header
                .vault_key_slots
                .iter()
                .any(|s| &s.fingerprint == fingerprint)
        } else {
            header.slots.iter().any(|s| &s.fingerprint == fingerprint)
        };

        if has_slot {
            if header.version >= 2 {
                // V2: remove from vault_key_slots + all env_slots, rotate env keys
                let old_vault_key =
                    envelope::unseal_vault_key(&header, actor_private_key, manifest.node_id)?;
                let old_cipher = VaultCipher::new(old_vault_key);

                envelope::remove_recipient_v2(&mut header, fingerprint);

                // Re-encrypt policy with existing vault key (vault key not rotated for hierarchy)
                if policy_path.exists() {
                    let mut policy = VaultPolicy::load_encrypted(&policy_path, &old_cipher)?;
                    policy.remove_member(fingerprint);
                    policy.save_encrypted(&policy_path, &old_cipher)?;
                }

                write_header(&members_path, &header, signing_key, manifest.node_id)?;
            } else {
                // V1: rotate master key
                let old_master_key =
                    envelope::unseal_master_key(&header, actor_private_key, manifest.node_id)?;
                let new_cipher = VaultCipher::generate();
                let pubkeys: Vec<X25519PublicKey> = remaining_pubkeys
                    .iter()
                    .filter(|(fp, _)| fp != fingerprint)
                    .map(|(_, pk)| pk.clone())
                    .collect();
                let new_header =
                    envelope::seal_master_key(new_cipher.key_bytes(), &pubkeys, manifest.node_id)?;
                write_header(&members_path, &new_header, signing_key, manifest.node_id)?;

                if policy_path.exists() {
                    let old_cipher = VaultCipher::new(old_master_key);
                    let mut policy = VaultPolicy::load_encrypted(&policy_path, &old_cipher)?;
                    policy.remove_member(fingerprint);
                    policy.save_encrypted(&policy_path, &new_cipher)?;
                }
            }

            affected.push(format!("node:{}", path));
        }
    }

    // Process linked vaults at this exact path
    let org_str = path.as_str();
    let vaults = vault_paths.list_vaults_for_org(&org_str, None)?;
    for vault_name in vaults {
        let vault_manifest_path = vault_paths.manifest_path(&vault_name);
        if let Ok(content) = std::fs::read_to_string(&vault_manifest_path) {
            if let Ok(vault_manifest) = crate::vault::VaultManifest::from_toml(&content) {
                if vault_manifest.org_path.as_deref() == Some(&org_str) {
                    let vault_members = vault_paths.members_path(&vault_name);
                    let vault_header =
                        read_header(&vault_members, None, Some(vault_manifest.vault_id))?;

                    let has_vault_slot = if vault_header.version >= 2 {
                        vault_header
                            .vault_key_slots
                            .iter()
                            .any(|s| &s.fingerprint == fingerprint)
                    } else {
                        vault_header
                            .slots
                            .iter()
                            .any(|s| &s.fingerprint == fingerprint)
                    };

                    if has_vault_slot {
                        if vault_header.version >= 2 {
                            // V2: remove from all slots, rotate env keys
                            let old_vault_key = envelope::unseal_vault_key(
                                &vault_header,
                                actor_private_key,
                                vault_manifest.vault_id,
                            )?;
                            let old_vault_cipher = VaultCipher::new(old_vault_key);

                            let mut vh = vault_header.clone();
                            envelope::remove_recipient_v2(&mut vh, fingerprint);

                            // Rotate env keys for remaining members
                            let remaining: Vec<X25519PublicKey> = remaining_pubkeys
                                .iter()
                                .filter(|(fp, _)| fp != fingerprint)
                                .map(|(_, pk)| pk.clone())
                                .collect();

                            for env_name in &vault_manifest.environments {
                                let new_env_key = envelope::rotate_env_key(
                                    &mut vh,
                                    env_name,
                                    &remaining,
                                    vault_manifest.vault_id,
                                )?;

                                let env_path = vault_paths.env_path(&vault_name, env_name);
                                if env_path.exists() {
                                    if let Ok(old_env_key) = envelope::unseal_env_key(
                                        &vault_header,
                                        env_name,
                                        actor_private_key,
                                        vault_manifest.vault_id,
                                    ) {
                                        let old_env_cipher = VaultCipher::new(old_env_key);
                                        let encrypted =
                                            crate::vault::env_file::read_encrypted_env(&env_path)?;
                                        let plaintext = crate::vault::env_file::decrypt_env(
                                            &encrypted,
                                            &old_env_cipher,
                                        )?;
                                        let new_env_cipher = VaultCipher::new(new_env_key);
                                        let re_encrypted = crate::vault::env_file::encrypt_env(
                                            &plaintext,
                                            &new_env_cipher,
                                            env_name,
                                        )?;
                                        crate::vault::env_file::write_encrypted_env(
                                            &env_path,
                                            &re_encrypted,
                                        )?;
                                    }
                                }
                            }

                            // Re-encrypt vault policy with existing vault key
                            let vault_policy_path = vault_paths.policy_path(&vault_name);
                            if vault_policy_path.exists() {
                                let policy = VaultPolicy::load_encrypted(
                                    &vault_policy_path,
                                    &old_vault_cipher,
                                )?;
                                policy.save_encrypted(&vault_policy_path, &old_vault_cipher)?;
                            }

                            write_header(
                                &vault_members,
                                &vh,
                                signing_key,
                                vault_manifest.vault_id,
                            )?;
                        } else {
                            // V1: rotate master key
                            let old_mk = envelope::unseal_master_key(
                                &vault_header,
                                actor_private_key,
                                vault_manifest.vault_id,
                            )?;
                            let new_cipher = VaultCipher::generate();
                            let pubkeys: Vec<X25519PublicKey> = remaining_pubkeys
                                .iter()
                                .filter(|(fp, _)| fp != fingerprint)
                                .map(|(_, pk)| pk.clone())
                                .collect();
                            let new_header = envelope::seal_master_key(
                                new_cipher.key_bytes(),
                                &pubkeys,
                                vault_manifest.vault_id,
                            )?;
                            write_header(
                                &vault_members,
                                &new_header,
                                signing_key,
                                vault_manifest.vault_id,
                            )?;

                            let vault_policy_path = vault_paths.policy_path(&vault_name);
                            if vault_policy_path.exists() {
                                let old_cipher = VaultCipher::new(old_mk);
                                let policy =
                                    VaultPolicy::load_encrypted(&vault_policy_path, &old_cipher)?;
                                policy.save_encrypted(&vault_policy_path, &new_cipher)?;
                            }

                            let env_dir = vault_paths.env_dir(&vault_name);
                            if env_dir.exists() {
                                let old_cipher = VaultCipher::new(old_mk);
                                for env_name in &vault_manifest.environments {
                                    let env_path = vault_paths.env_path(&vault_name, env_name);
                                    if env_path.exists() {
                                        let encrypted =
                                            crate::vault::env_file::read_encrypted_env(&env_path)?;
                                        let plaintext = crate::vault::env_file::decrypt_env(
                                            &encrypted,
                                            &old_cipher,
                                        )?;
                                        let re_encrypted = crate::vault::env_file::encrypt_env(
                                            &plaintext,
                                            &new_cipher,
                                            env_name,
                                        )?;
                                        crate::vault::env_file::write_encrypted_env(
                                            &env_path,
                                            &re_encrypted,
                                        )?;
                                    }
                                }
                            }
                        }

                        affected.push(format!("vault:{}", vault_name));
                    }
                }
            }
        }
    }

    // Recurse into children
    let children = hierarchy_paths.list_children(path)?;
    for child_name in children {
        let child_path = path.child(&child_name)?;
        remove_recipient_from_subtree(
            hierarchy_paths,
            vault_paths,
            &child_path,
            fingerprint,
            actor_private_key,
            remaining_pubkeys,
            signing_key,
            affected,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope;
    use crate::crypto::keys::{SigningKeyPair, X25519PrivateKey};

    #[test]
    fn test_read_write_header_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let master_key = [0xABu8; 32];
        let alice = X25519PrivateKey::generate();
        let signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let header =
            envelope::seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();

        write_header(&path, &header, &signer, vault_id).unwrap();
        let loaded = read_header(&path, Some(&signer.verifying_key()), Some(vault_id)).unwrap();
        assert_eq!(loaded.slots.len(), 1);

        let recovered = envelope::unseal_master_key(&loaded, &alice, vault_id).unwrap();
        assert_eq!(recovered, master_key);
    }

    #[test]
    fn test_read_header_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.cbor");
        let header = read_header(&path, None, None).unwrap();
        assert!(header.slots.is_empty());
    }

    #[test]
    fn test_add_recipient_to_node_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let master_key = [0xCDu8; 32];
        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();
        let signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let header =
            envelope::seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();
        write_header(&path, &header, &signer, vault_id).unwrap();

        // Add bob
        add_recipient_to_node(
            &path,
            &master_key,
            &bob.public_key(),
            vault_id,
            &signer,
            None,
        )
        .unwrap();
        let h = read_header(&path, None, None).unwrap();
        assert_eq!(h.slots.len(), 2);

        // Add bob again — should be idempotent
        add_recipient_to_node(
            &path,
            &master_key,
            &bob.public_key(),
            vault_id,
            &signer,
            None,
        )
        .unwrap();
        let h = read_header(&path, None, None).unwrap();
        assert_eq!(h.slots.len(), 2);
    }

    #[test]
    fn test_read_header_rejects_wrong_signer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let master_key = [0xEFu8; 32];
        let alice = X25519PrivateKey::generate();
        let signer = SigningKeyPair::generate();
        let other_signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let header =
            envelope::seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();
        write_header(&path, &header, &signer, vault_id).unwrap();

        // Verify with wrong key should fail
        let result = read_header(&path, Some(&other_signer.verifying_key()), Some(vault_id));
        assert!(result.is_err());
    }
}
