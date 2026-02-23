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
}
