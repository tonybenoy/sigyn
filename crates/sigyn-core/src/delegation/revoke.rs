use std::collections::BTreeMap;

use crate::crypto::envelope::{self, EnvelopeHeader};
use crate::crypto::keys::{KeyFingerprint, X25519PublicKey};
use crate::crypto::vault_cipher::VaultCipher;
use crate::error::{Result, SigynError};
use crate::policy::storage::VaultPolicy;

#[derive(Debug)]
pub struct RevocationResult {
    pub directly_revoked: KeyFingerprint,
    pub cascade_revoked: Vec<KeyFingerprint>,
    pub master_key_rotated: bool,
}

pub struct RevocationResultV2 {
    pub directly_revoked: KeyFingerprint,
    pub cascade_revoked: Vec<KeyFingerprint>,
    /// New vault-level cipher (None if vault key was not rotated).
    pub new_vault_cipher: Option<VaultCipher>,
    /// Per-env new ciphers for environments whose keys were rotated.
    pub rotated_env_ciphers: BTreeMap<String, VaultCipher>,
    /// Which environments were affected by the revocation.
    pub affected_envs: Vec<String>,
}

/// Collect all fingerprints that were transitively delegated by `root`.
/// Walks the policy members to find children whose `delegated_by` matches `root`,
/// then recursively finds their children, and so on.
fn collect_cascade(root: &KeyFingerprint, policy: &VaultPolicy) -> Vec<KeyFingerprint> {
    let mut revoked = Vec::new();
    let mut queue = vec![root.clone()];

    while let Some(parent) = queue.pop() {
        for member in policy.members.values() {
            if let Some(ref delegator) = member.delegated_by {
                if delegator == &parent && !revoked.contains(&member.fingerprint) {
                    revoked.push(member.fingerprint.clone());
                    queue.push(member.fingerprint.clone());
                }
            }
        }
    }

    revoked
}

/// Revoke a member from the vault, optionally cascading to all members they invited.
/// Returns the revocation result and a new VaultCipher if master key rotation happened.
///
/// The caller must supply `remaining_pubkeys` containing the (fingerprint, pubkey) pairs
/// for every member that is NOT being revoked (and not the target fingerprint). This is
/// used to rebuild the envelope header with a fresh master key so that revoked members
/// can no longer decrypt anything.
pub fn revoke_member(
    fingerprint: &KeyFingerprint,
    cascade: bool,
    policy: &mut VaultPolicy,
    header: &mut EnvelopeHeader,
    vault_id: uuid::Uuid,
    remaining_pubkeys: &[(KeyFingerprint, X25519PublicKey)],
) -> Result<(RevocationResult, Option<VaultCipher>)> {
    // 1. Verify the target member exists
    if policy.get_member(fingerprint).is_none() {
        return Err(SigynError::MemberNotFound(fingerprint.to_hex()));
    }

    // 2. If cascade, collect all transitive delegatees
    let cascade_revoked = if cascade {
        collect_cascade(fingerprint, policy)
    } else {
        Vec::new()
    };

    // 3. Build the full list of fingerprints to revoke
    let mut all_revoked = vec![fingerprint.clone()];
    all_revoked.extend(cascade_revoked.iter().cloned());

    // 4. Remove all affected members from policy
    for fp in &all_revoked {
        policy.remove_member(fp);
    }

    // 5. Generate new master key and rebuild envelope header from scratch
    //    using only the remaining (non-revoked) members' public keys.
    let new_cipher = VaultCipher::generate();
    let pubkeys: Vec<X25519PublicKey> = remaining_pubkeys
        .iter()
        .filter(|(fp, _)| !all_revoked.contains(fp))
        .map(|(_, pk)| pk.clone())
        .collect();

    let new_header = envelope::seal_master_key(new_cipher.key_bytes(), &pubkeys, vault_id)?;
    *header = new_header;

    let result = RevocationResult {
        directly_revoked: fingerprint.clone(),
        cascade_revoked,
        master_key_rotated: true,
    };

    Ok((result, Some(new_cipher)))
}

/// Revoke a member from a v2 vault with per-environment key isolation.
///
/// Instead of rotating a single master key, this:
/// 1. Determines which environments the revoked member(s) had access to
/// 2. Removes them from the policy
/// 3. Removes their vault_key_slots (no vault key rotation — it only protects metadata)
/// 4. For each affected environment: rotates that env's key and re-seals for remaining members
///
/// The caller must re-encrypt only the affected env files with the new ciphers.
///
/// `member_env_access` maps fingerprint → list of env names they had access to (from allowed_envs).
/// `remaining_pubkeys` includes all members (before revocation) with their pubkeys.
pub fn revoke_member_v2(
    fingerprint: &KeyFingerprint,
    cascade: bool,
    policy: &mut VaultPolicy,
    header: &mut EnvelopeHeader,
    vault_id: uuid::Uuid,
    remaining_pubkeys: &[(KeyFingerprint, X25519PublicKey)],
    member_env_access: &BTreeMap<KeyFingerprint, Vec<String>>,
) -> Result<(RevocationResultV2,)> {
    // 1. Verify the target member exists
    if policy.get_member(fingerprint).is_none() {
        return Err(SigynError::MemberNotFound(fingerprint.to_hex()));
    }

    // 2. If cascade, collect all transitive delegatees
    let cascade_revoked = if cascade {
        collect_cascade(fingerprint, policy)
    } else {
        Vec::new()
    };

    // 3. Build the full list of fingerprints to revoke
    let mut all_revoked = vec![fingerprint.clone()];
    all_revoked.extend(cascade_revoked.iter().cloned());

    // 4. Determine which environments are affected (union of revoked members' env access)
    let mut affected_envs = std::collections::BTreeSet::new();
    for fp in &all_revoked {
        if let Some(envs) = member_env_access.get(fp) {
            for env in envs {
                affected_envs.insert(env.clone());
            }
        }
    }

    // 5. Remove all affected members from policy
    for fp in &all_revoked {
        policy.remove_member(fp);
    }

    // 6. Remove from vault_key_slots (but don't rotate vault key)
    for fp in &all_revoked {
        envelope::remove_recipient_v2(header, fp);
    }

    // 7. For each affected environment, rotate the env key for remaining members
    let mut rotated_env_ciphers = BTreeMap::new();
    let non_revoked_pubkeys: Vec<&(KeyFingerprint, X25519PublicKey)> = remaining_pubkeys
        .iter()
        .filter(|(fp, _)| !all_revoked.contains(fp))
        .collect();

    for env_name in &affected_envs {
        // Find which remaining members should have access to this env
        let env_recipients: Vec<X25519PublicKey> = non_revoked_pubkeys
            .iter()
            .filter(|(fp, _)| {
                // Check if this remaining member has access to this env
                member_env_access
                    .get(fp)
                    .is_some_and(|envs| envs.contains(env_name))
            })
            .map(|(_, pk)| pk.clone())
            .collect();

        let new_env_key = envelope::rotate_env_key(header, env_name, &env_recipients, vault_id)?;
        rotated_env_ciphers.insert(env_name.clone(), VaultCipher::new(new_env_key));
    }

    let result = RevocationResultV2 {
        directly_revoked: fingerprint.clone(),
        cascade_revoked,
        new_vault_cipher: None, // Vault key is not rotated in v2
        rotated_env_ciphers,
        affected_envs: affected_envs.into_iter().collect(),
    };

    Ok((result,))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::X25519PrivateKey;
    use crate::policy::member::MemberPolicy;
    use crate::policy::roles::Role;

    /// Helper: create a member policy with a delegated_by field set.
    fn make_member(
        fp: KeyFingerprint,
        role: Role,
        delegated_by: Option<KeyFingerprint>,
    ) -> MemberPolicy {
        let mut m = MemberPolicy::new(fp, role);
        m.delegated_by = delegated_by;
        m
    }

    #[test]
    fn test_collect_cascade_empty() {
        let policy = VaultPolicy::new();
        let fp = KeyFingerprint([1u8; 16]);
        let result = collect_cascade(&fp, &policy);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_cascade_direct_children() {
        let mut policy = VaultPolicy::new();
        let root = KeyFingerprint([1u8; 16]);
        let child1 = KeyFingerprint([2u8; 16]);
        let child2 = KeyFingerprint([3u8; 16]);
        let unrelated = KeyFingerprint([4u8; 16]);

        policy.add_member(make_member(root.clone(), Role::Manager, None));
        policy.add_member(make_member(
            child1.clone(),
            Role::Contributor,
            Some(root.clone()),
        ));
        policy.add_member(make_member(
            child2.clone(),
            Role::ReadOnly,
            Some(root.clone()),
        ));
        policy.add_member(make_member(unrelated.clone(), Role::Contributor, None));

        let result = collect_cascade(&root, &policy);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&child1));
        assert!(result.contains(&child2));
        assert!(!result.contains(&unrelated));
    }

    #[test]
    fn test_collect_cascade_transitive() {
        let mut policy = VaultPolicy::new();
        let root = KeyFingerprint([1u8; 16]);
        let child = KeyFingerprint([2u8; 16]);
        let grandchild = KeyFingerprint([3u8; 16]);

        policy.add_member(make_member(root.clone(), Role::Manager, None));
        policy.add_member(make_member(
            child.clone(),
            Role::Manager,
            Some(root.clone()),
        ));
        policy.add_member(make_member(
            grandchild.clone(),
            Role::ReadOnly,
            Some(child.clone()),
        ));

        let result = collect_cascade(&root, &policy);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&child));
        assert!(result.contains(&grandchild));
    }

    #[test]
    fn test_revoke_member_no_cascade() {
        let vault_id = uuid::Uuid::new_v4();
        let owner_key = X25519PrivateKey::generate();
        let member_key = X25519PrivateKey::generate();
        let child_key = X25519PrivateKey::generate();

        let owner_fp = owner_key.public_key().fingerprint();
        let member_fp = member_key.public_key().fingerprint();
        let child_fp = child_key.public_key().fingerprint();

        let mut policy = VaultPolicy::new();
        policy.add_member(make_member(member_fp.clone(), Role::Manager, None));
        policy.add_member(make_member(
            child_fp.clone(),
            Role::ReadOnly,
            Some(member_fp.clone()),
        ));

        let mut header = envelope::seal_master_key(
            &[0xABu8; 32],
            &[
                owner_key.public_key(),
                member_key.public_key(),
                child_key.public_key(),
            ],
            vault_id,
        )
        .unwrap();

        let remaining = vec![
            (owner_fp.clone(), owner_key.public_key()),
            (member_fp.clone(), member_key.public_key()),
            (child_fp.clone(), child_key.public_key()),
        ];

        let (result, new_cipher) = revoke_member(
            &member_fp,
            false,
            &mut policy,
            &mut header,
            vault_id,
            &remaining,
        )
        .unwrap();

        assert_eq!(result.directly_revoked, member_fp);
        assert!(result.cascade_revoked.is_empty());
        assert!(result.master_key_rotated);
        assert!(new_cipher.is_some());

        // member_fp was removed from policy
        assert!(policy.get_member(&member_fp).is_none());
        // child_fp was NOT removed (no cascade)
        assert!(policy.get_member(&child_fp).is_some());

        // Header should have 2 slots: owner + child (member was excluded)
        assert_eq!(header.slots.len(), 2);

        // Owner can unseal the new master key
        let new_mk = envelope::unseal_master_key(&header, &owner_key, vault_id).unwrap();
        assert_eq!(new_mk, *new_cipher.unwrap().key_bytes());
    }

    #[test]
    fn test_revoke_member_with_cascade() {
        let vault_id = uuid::Uuid::new_v4();
        let owner_key = X25519PrivateKey::generate();
        let member_key = X25519PrivateKey::generate();
        let child_key = X25519PrivateKey::generate();
        let grandchild_key = X25519PrivateKey::generate();

        let owner_fp = owner_key.public_key().fingerprint();
        let member_fp = member_key.public_key().fingerprint();
        let child_fp = child_key.public_key().fingerprint();
        let grandchild_fp = grandchild_key.public_key().fingerprint();

        let mut policy = VaultPolicy::new();
        policy.add_member(make_member(member_fp.clone(), Role::Manager, None));
        policy.add_member(make_member(
            child_fp.clone(),
            Role::Contributor,
            Some(member_fp.clone()),
        ));
        policy.add_member(make_member(
            grandchild_fp.clone(),
            Role::ReadOnly,
            Some(child_fp.clone()),
        ));

        let mut header = envelope::seal_master_key(
            &[0xCDu8; 32],
            &[
                owner_key.public_key(),
                member_key.public_key(),
                child_key.public_key(),
                grandchild_key.public_key(),
            ],
            vault_id,
        )
        .unwrap();

        let remaining = vec![
            (owner_fp.clone(), owner_key.public_key()),
            (member_fp.clone(), member_key.public_key()),
            (child_fp.clone(), child_key.public_key()),
            (grandchild_fp.clone(), grandchild_key.public_key()),
        ];

        let (result, new_cipher) = revoke_member(
            &member_fp,
            true,
            &mut policy,
            &mut header,
            vault_id,
            &remaining,
        )
        .unwrap();

        assert_eq!(result.directly_revoked, member_fp);
        assert_eq!(result.cascade_revoked.len(), 2);
        assert!(result.cascade_revoked.contains(&child_fp));
        assert!(result.cascade_revoked.contains(&grandchild_fp));
        assert!(result.master_key_rotated);

        // All three were removed from policy
        assert!(policy.get_member(&member_fp).is_none());
        assert!(policy.get_member(&child_fp).is_none());
        assert!(policy.get_member(&grandchild_fp).is_none());

        // Only owner slot remains in header
        assert_eq!(header.slots.len(), 1);
        let new_mk = envelope::unseal_master_key(&header, &owner_key, vault_id).unwrap();
        assert_eq!(new_mk, *new_cipher.unwrap().key_bytes());

        // Revoked members cannot unseal
        assert!(envelope::unseal_master_key(&header, &member_key, vault_id).is_err());
        assert!(envelope::unseal_master_key(&header, &child_key, vault_id).is_err());
        assert!(envelope::unseal_master_key(&header, &grandchild_key, vault_id).is_err());
    }

    #[test]
    fn test_revoke_nonexistent_member_errors() {
        let vault_id = uuid::Uuid::new_v4();
        let mut policy = VaultPolicy::new();
        let fp = KeyFingerprint([99u8; 16]);
        let mut header = EnvelopeHeader::default();

        let result = revoke_member(&fp, false, &mut policy, &mut header, vault_id, &[]);
        assert!(result.is_err());
    }

    // --- V2 revocation tests ---

    #[test]
    fn test_revoke_member_v2_per_env_rotation() {
        let vault_id = uuid::Uuid::new_v4();
        let owner_key = X25519PrivateKey::generate();
        let member_key = X25519PrivateKey::generate();

        let owner_fp = owner_key.public_key().fingerprint();
        let member_fp = member_key.public_key().fingerprint();

        let mut policy = VaultPolicy::new();
        let mut member = MemberPolicy::new(member_fp.clone(), Role::Contributor);
        member.allowed_envs = vec!["dev".into(), "staging".into()];
        policy.add_member(member);

        // Build v2 header
        let vault_key = [0xAAu8; 32];
        let dev_key = [0xBBu8; 32];
        let staging_key = [0xCCu8; 32];
        let prod_key = [0xDDu8; 32];

        let mut env_keys = BTreeMap::new();
        env_keys.insert("dev".into(), dev_key);
        env_keys.insert("staging".into(), staging_key);
        env_keys.insert("prod".into(), prod_key);

        let mut env_recipients = BTreeMap::new();
        env_recipients.insert(
            "dev".into(),
            vec![owner_key.public_key(), member_key.public_key()],
        );
        env_recipients.insert(
            "staging".into(),
            vec![owner_key.public_key(), member_key.public_key()],
        );
        env_recipients.insert("prod".into(), vec![owner_key.public_key()]);

        let mut header = envelope::seal_v2(
            &vault_key,
            &env_keys,
            &[owner_key.public_key(), member_key.public_key()],
            &env_recipients,
            vault_id,
        )
        .unwrap();

        let remaining = vec![
            (owner_fp.clone(), owner_key.public_key()),
            (member_fp.clone(), member_key.public_key()),
        ];

        let mut member_envs = BTreeMap::new();
        // Owner has access to all envs
        member_envs.insert(
            owner_fp.clone(),
            vec!["dev".into(), "staging".into(), "prod".into()],
        );
        // Member has dev + staging
        member_envs.insert(member_fp.clone(), vec!["dev".into(), "staging".into()]);

        let (result,) = super::revoke_member_v2(
            &member_fp,
            false,
            &mut policy,
            &mut header,
            vault_id,
            &remaining,
            &member_envs,
        )
        .unwrap();

        assert_eq!(result.directly_revoked, member_fp);
        assert!(result.cascade_revoked.is_empty());
        assert!(result.new_vault_cipher.is_none()); // vault key not rotated

        // dev and staging should have been rotated
        assert_eq!(result.affected_envs.len(), 2);
        assert!(result.affected_envs.contains(&"dev".to_string()));
        assert!(result.affected_envs.contains(&"staging".to_string()));
        assert_eq!(result.rotated_env_ciphers.len(), 2);

        // Member removed from policy
        assert!(policy.get_member(&member_fp).is_none());

        // Owner can still unseal vault key
        assert!(envelope::unseal_vault_key(&header, &owner_key, vault_id).is_ok());

        // Owner can unseal new dev/staging keys
        let new_dev = envelope::unseal_env_key(&header, "dev", &owner_key, vault_id).unwrap();
        assert_ne!(dev_key, new_dev); // Key was rotated

        // Member cannot unseal anything
        assert!(envelope::unseal_vault_key(&header, &member_key, vault_id).is_err());
        assert!(envelope::unseal_env_key(&header, "dev", &member_key, vault_id).is_err());

        // Prod was NOT affected (member didn't have access)
        let prod_still = envelope::unseal_env_key(&header, "prod", &owner_key, vault_id).unwrap();
        assert_eq!(prod_key, prod_still); // Prod key unchanged
    }
}
