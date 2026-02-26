use std::path::Path;

use uuid::Uuid;

use super::manifest::NodeManifest;
use super::path::{HierarchyPaths, OrgPath};
use crate::crypto::envelope::{self, EnvelopeHeader};
use crate::crypto::keys::{
    KeyFingerprint, SigningKeyPair, VerifyingKeyWrapper, X25519PrivateKey, X25519PublicKey,
};
use crate::crypto::vault_cipher::VaultCipher;
use crate::error::Result;
use crate::policy::storage::{VaultPolicy, VaultPolicyExt};
use crate::vault::VaultPaths;

/// Read an envelope header from a signed (SGSN) file.
/// If the file doesn't exist, returns a default empty header.
/// Always verifies the signature.
fn read_header(
    path: &Path,
    verifying_key: &VerifyingKeyWrapper,
    domain_id: Uuid,
) -> Result<EnvelopeHeader> {
    if !path.exists() {
        return Ok(EnvelopeHeader::default());
    }
    let data = std::fs::read(path)?;
    envelope::verify_and_load_header(&data, domain_id, verifying_key)
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
    verifying_key: &VerifyingKeyWrapper,
) -> Result<()> {
    let mut header = read_header(members_path, verifying_key, domain_id)?;

    envelope::add_vault_key_recipient(&mut header, master_key, new_pubkey, domain_id)?;
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

        // Unseal the node's vault key using actor's private key
        let vk = signing_key.verifying_key();
        let header = read_header(&members_path, &vk, manifest.node_id)?;
        let master_key = envelope::unseal_vault_key(&header, actor_private_key, manifest.node_id)?;

        // Add recipient to this node
        add_recipient_to_node(
            &members_path,
            &master_key,
            new_pubkey,
            manifest.node_id,
            signing_key,
            &vk,
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
                    let vk = signing_key.verifying_key();
                    let vault_header = read_header(&vault_members, &vk, vault_manifest.vault_id)?;
                    let vault_mk = envelope::unseal_vault_key(
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
                        &vk,
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

        let vk = signing_key.verifying_key();
        let mut header = read_header(&members_path, &vk, manifest.node_id)?;

        let has_slot = header
            .vault_key_slots
            .iter()
            .any(|s| &s.fingerprint == fingerprint);

        if has_slot {
            let old_vault_key =
                envelope::unseal_vault_key(&header, actor_private_key, manifest.node_id)?;
            let old_cipher = VaultCipher::new(old_vault_key);

            envelope::remove_recipient_v2(&mut header, fingerprint);

            // Re-encrypt policy with existing vault key (vault key not rotated for hierarchy)
            if policy_path.exists() {
                let mut policy =
                    VaultPolicy::load_signed(&policy_path, &old_cipher, &vk, &manifest.node_id)?;
                policy.remove_member(fingerprint);
                policy.save_signed(&policy_path, &old_cipher, signing_key, &manifest.node_id)?;
            }

            write_header(&members_path, &header, signing_key, manifest.node_id)?;

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
                    let vk = signing_key.verifying_key();
                    let vault_header = read_header(&vault_members, &vk, vault_manifest.vault_id)?;

                    let has_vault_slot = vault_header
                        .vault_key_slots
                        .iter()
                        .any(|s| &s.fingerprint == fingerprint);

                    if has_vault_slot {
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
                            let policy = VaultPolicy::load_signed(
                                &vault_policy_path,
                                &old_vault_cipher,
                                &vk,
                                &vault_manifest.vault_id,
                            )?;
                            policy.save_signed(
                                &vault_policy_path,
                                &old_vault_cipher,
                                signing_key,
                                &vault_manifest.vault_id,
                            )?;
                        }

                        write_header(&vault_members, &vh, signing_key, vault_manifest.vault_id)?;

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

    use std::collections::BTreeMap;

    fn make_v2_header(
        vault_key: &[u8; 32],
        recipients: &[crate::crypto::keys::X25519PublicKey],
        vault_id: Uuid,
    ) -> EnvelopeHeader {
        envelope::seal_v2(
            vault_key,
            &BTreeMap::new(),
            recipients,
            &BTreeMap::new(),
            vault_id,
        )
        .unwrap()
    }

    #[test]
    fn test_read_write_header_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let vault_key = [0xABu8; 32];
        let alice = X25519PrivateKey::generate();
        let signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let header = make_v2_header(&vault_key, &[alice.public_key()], vault_id);

        write_header(&path, &header, &signer, vault_id).unwrap();
        let loaded = read_header(&path, &signer.verifying_key(), vault_id).unwrap();
        assert_eq!(loaded.vault_key_slots.len(), 1);

        let recovered = envelope::unseal_vault_key(&loaded, &alice, vault_id).unwrap();
        assert_eq!(recovered, vault_key);
    }

    #[test]
    fn test_read_header_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.cbor");
        let signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();
        let header = read_header(&path, &signer.verifying_key(), vault_id).unwrap();
        assert!(header.vault_key_slots.is_empty());
    }

    #[test]
    fn test_add_recipient_to_node_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let vault_key = [0xCDu8; 32];
        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();
        let signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let header = make_v2_header(&vault_key, &[alice.public_key()], vault_id);
        write_header(&path, &header, &signer, vault_id).unwrap();

        // Add bob
        let vk = signer.verifying_key();
        add_recipient_to_node(&path, &vault_key, &bob.public_key(), vault_id, &signer, &vk)
            .unwrap();
        let h = read_header(&path, &vk, vault_id).unwrap();
        assert_eq!(h.vault_key_slots.len(), 2);

        // Add bob again — should be idempotent
        add_recipient_to_node(&path, &vault_key, &bob.public_key(), vault_id, &signer, &vk)
            .unwrap();
        let h = read_header(&path, &vk, vault_id).unwrap();
        assert_eq!(h.vault_key_slots.len(), 2);
    }

    #[test]
    fn test_read_header_rejects_wrong_signer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let vault_key = [0xEFu8; 32];
        let alice = X25519PrivateKey::generate();
        let signer = SigningKeyPair::generate();
        let other_signer = SigningKeyPair::generate();
        let vault_id = Uuid::new_v4();

        let header = make_v2_header(&vault_key, &[alice.public_key()], vault_id);
        write_header(&path, &header, &signer, vault_id).unwrap();

        // Verify with wrong key should fail
        let result = read_header(&path, &other_signer.verifying_key(), vault_id);
        assert!(result.is_err());
    }
}
