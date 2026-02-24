use std::path::Path;

use uuid::Uuid;

use super::manifest::NodeManifest;
use super::path::{HierarchyPaths, OrgPath};
use crate::crypto::envelope::{self, EnvelopeHeader};
use crate::crypto::keys::{KeyFingerprint, X25519PrivateKey, X25519PublicKey};
use crate::crypto::vault_cipher::VaultCipher;
use crate::error::{Result, SigynError};
use crate::policy::storage::{VaultPolicy, VaultPolicyExt};
use crate::vault::VaultPaths;

/// Read an envelope header from a CBOR file.
fn read_header(path: &Path) -> Result<EnvelopeHeader> {
    if !path.exists() {
        return Ok(EnvelopeHeader::default());
    }
    let data = std::fs::read(path)?;
    ciborium::from_reader(data.as_slice()).map_err(|e| SigynError::CborDecode(e.to_string()))
}

/// Write an envelope header to a CBOR file.
fn write_header(path: &Path, header: &EnvelopeHeader) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::new();
    ciborium::into_writer(header, &mut buf).map_err(|e| SigynError::CborEncode(e.to_string()))?;
    std::fs::write(path, buf)?;
    Ok(())
}

/// Add a recipient slot to a single node's envelope.
fn add_recipient_to_node(
    members_path: &Path,
    master_key: &[u8; 32],
    new_pubkey: &X25519PublicKey,
    domain_id: Uuid,
) -> Result<()> {
    let mut header = read_header(members_path)?;
    // Check if slot already exists
    let new_fp = new_pubkey.fingerprint();
    if header.slots.iter().any(|s| s.fingerprint == new_fp) {
        return Ok(()); // Already has a slot
    }
    envelope::add_recipient(&mut header, master_key, new_pubkey, domain_id)?;
    write_header(members_path, &header)?;
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
) -> Result<Vec<String>> {
    let mut affected = Vec::new();

    // Process the target node itself
    add_recipient_to_subtree(
        hierarchy_paths,
        vault_paths,
        org_path,
        actor_private_key,
        new_pubkey,
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
    affected: &mut Vec<String>,
) -> Result<()> {
    let members_path = hierarchy_paths.members_path(path);
    let manifest_path = hierarchy_paths.manifest_path(path);

    if manifest_path.exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest = NodeManifest::from_toml(&manifest_content)?;

        // Unseal the node's master key using actor's private key
        let header = read_header(&members_path)?;
        let master_key = envelope::unseal_master_key(&header, actor_private_key, manifest.node_id)?;

        // Add recipient to this node
        add_recipient_to_node(&members_path, &master_key, new_pubkey, manifest.node_id)?;
        affected.push(format!("node:{}", path));
    }

    // Process linked vaults
    let org_str = path.as_str();
    let vaults = vault_paths.list_vaults_for_org(&org_str)?;
    for vault_name in vaults {
        let vault_manifest_path = vault_paths.manifest_path(&vault_name);
        if let Ok(content) = std::fs::read_to_string(&vault_manifest_path) {
            if let Ok(vault_manifest) = crate::vault::VaultManifest::from_toml(&content) {
                // Only process vaults directly at this org_path level
                if vault_manifest.org_path.as_deref() == Some(&org_str) {
                    let vault_members = vault_paths.members_path(&vault_name);
                    let vault_header = read_header(&vault_members)?;
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
) -> Result<Vec<String>> {
    let mut affected = Vec::new();

    remove_recipient_from_subtree(
        hierarchy_paths,
        vault_paths,
        org_path,
        fingerprint,
        actor_private_key,
        remaining_pubkeys,
        &mut affected,
    )?;

    Ok(affected)
}

fn remove_recipient_from_subtree(
    hierarchy_paths: &HierarchyPaths,
    vault_paths: &VaultPaths,
    path: &OrgPath,
    fingerprint: &KeyFingerprint,
    actor_private_key: &X25519PrivateKey,
    remaining_pubkeys: &[(KeyFingerprint, X25519PublicKey)],
    affected: &mut Vec<String>,
) -> Result<()> {
    let members_path = hierarchy_paths.members_path(path);
    let manifest_path = hierarchy_paths.manifest_path(path);
    let policy_path = hierarchy_paths.policy_path(path);

    if manifest_path.exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest = NodeManifest::from_toml(&manifest_content)?;

        let header = read_header(&members_path)?;

        // Check if the target even has a slot here
        if header.slots.iter().any(|s| &s.fingerprint == fingerprint) {
            // Unseal current master key
            let old_master_key =
                envelope::unseal_master_key(&header, actor_private_key, manifest.node_id)?;

            // Generate new master key
            let new_cipher = VaultCipher::generate();

            // Rebuild header with only remaining (non-revoked) pubkeys
            let pubkeys: Vec<X25519PublicKey> = remaining_pubkeys
                .iter()
                .filter(|(fp, _)| fp != fingerprint)
                .map(|(_, pk)| pk.clone())
                .collect();

            let new_header =
                envelope::seal_master_key(new_cipher.key_bytes(), &pubkeys, manifest.node_id)?;
            write_header(&members_path, &new_header)?;

            // Re-encrypt policy with new master key if it exists
            if policy_path.exists() {
                let old_cipher = VaultCipher::new(old_master_key);
                let mut policy = VaultPolicy::load_encrypted(&policy_path, &old_cipher)?;
                // Also remove from node-level policy
                policy.remove_member(fingerprint);
                policy.save_encrypted(&policy_path, &new_cipher)?;
            }

            affected.push(format!("node:{}", path));
        }
    }

    // Process linked vaults at this exact path
    let org_str = path.as_str();
    let vaults = vault_paths.list_vaults_for_org(&org_str)?;
    for vault_name in vaults {
        let vault_manifest_path = vault_paths.manifest_path(&vault_name);
        if let Ok(content) = std::fs::read_to_string(&vault_manifest_path) {
            if let Ok(vault_manifest) = crate::vault::VaultManifest::from_toml(&content) {
                if vault_manifest.org_path.as_deref() == Some(&org_str) {
                    let vault_members = vault_paths.members_path(&vault_name);
                    let vault_header = read_header(&vault_members)?;

                    if vault_header
                        .slots
                        .iter()
                        .any(|s| &s.fingerprint == fingerprint)
                    {
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
                        write_header(&vault_members, &new_header)?;

                        // Re-encrypt vault policy
                        let vault_policy_path = vault_paths.policy_path(&vault_name);
                        if vault_policy_path.exists() {
                            let old_cipher = VaultCipher::new(old_mk);
                            let policy =
                                VaultPolicy::load_encrypted(&vault_policy_path, &old_cipher)?;
                            policy.save_encrypted(&vault_policy_path, &new_cipher)?;
                        }

                        // Re-encrypt env files
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
            affected,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope;
    use crate::crypto::keys::X25519PrivateKey;

    #[test]
    fn test_read_write_header_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let master_key = [0xABu8; 32];
        let alice = X25519PrivateKey::generate();
        let vault_id = Uuid::new_v4();

        let header =
            envelope::seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();

        write_header(&path, &header).unwrap();
        let loaded = read_header(&path).unwrap();
        assert_eq!(loaded.slots.len(), 1);

        let recovered = envelope::unseal_master_key(&loaded, &alice, vault_id).unwrap();
        assert_eq!(recovered, master_key);
    }

    #[test]
    fn test_read_header_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.cbor");
        let header = read_header(&path).unwrap();
        assert!(header.slots.is_empty());
    }

    #[test]
    fn test_add_recipient_to_node_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.cbor");

        let master_key = [0xCDu8; 32];
        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();
        let vault_id = Uuid::new_v4();

        let header =
            envelope::seal_master_key(&master_key, &[alice.public_key()], vault_id).unwrap();
        write_header(&path, &header).unwrap();

        // Add bob
        add_recipient_to_node(&path, &master_key, &bob.public_key(), vault_id).unwrap();
        let h = read_header(&path).unwrap();
        assert_eq!(h.slots.len(), 2);

        // Add bob again — should be idempotent
        add_recipient_to_node(&path, &master_key, &bob.public_key(), vault_id).unwrap();
        let h = read_header(&path).unwrap();
        assert_eq!(h.slots.len(), 2);
    }
}
