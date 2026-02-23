use sigyn_core::crypto::envelope::{add_recipient, seal_master_key, unseal_master_key};
use sigyn_core::crypto::keys::{KeyFingerprint, X25519PrivateKey};
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::delegation::revoke::revoke_member;
use sigyn_core::policy::member::MemberPolicy;
use sigyn_core::policy::roles::Role;
use sigyn_core::policy::storage::VaultPolicy;
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::env_file::{decrypt_env, encrypt_env, PlaintextEnv};
use uuid::Uuid;

/// Helper to create a MemberPolicy with an optional delegated_by field.
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
fn test_revocation_makes_old_keys_useless() {
    let vault_id = Uuid::new_v4();

    // 1. Create owner + 2 members
    let owner_key = X25519PrivateKey::generate();
    let member_a_key = X25519PrivateKey::generate();
    let member_b_key = X25519PrivateKey::generate();

    let owner_fp = owner_key.public_key().fingerprint();
    let member_a_fp = member_a_key.public_key().fingerprint();
    let member_b_fp = member_b_key.public_key().fingerprint();

    // Seal master key for all three
    let original_master_key = [0xABu8; 32];
    let mut header = seal_master_key(
        &original_master_key,
        &[
            owner_key.public_key(),
            member_a_key.public_key(),
            member_b_key.public_key(),
        ],
        vault_id,
    )
    .unwrap();
    assert_eq!(header.slots.len(), 3);

    // Build policy: member B was delegated by owner (top-level), member A is independent
    let mut policy = VaultPolicy::new();
    policy.add_member(make_member(member_a_fp.clone(), Role::Contributor, None));
    policy.add_member(make_member(
        member_b_fp.clone(),
        Role::Contributor,
        Some(owner_fp.clone()),
    ));

    // 2. Set secrets using the original master key
    let original_cipher = VaultCipher::new(original_master_key);
    let mut env = PlaintextEnv::new();
    env.set(
        "DB_URL".into(),
        SecretValue::String("postgres://localhost".into()),
        &owner_fp,
    );
    env.set(
        "API_KEY".into(),
        SecretValue::String("sk-secret-123".into()),
        &owner_fp,
    );
    let encrypted_before = encrypt_env(&env, &original_cipher, "dev").unwrap();

    // Verify all three can currently unseal
    assert!(unseal_master_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_master_key(&header, &member_a_key, vault_id).is_ok());
    assert!(unseal_master_key(&header, &member_b_key, vault_id).is_ok());

    // 3. Revoke member B with cascade
    let remaining_pubkeys = vec![
        (owner_fp.clone(), owner_key.public_key()),
        (member_a_fp.clone(), member_a_key.public_key()),
        (member_b_fp.clone(), member_b_key.public_key()),
    ];

    let (result, new_cipher_opt) = revoke_member(
        &member_b_fp,
        true,
        &mut policy,
        &mut header,
        vault_id,
        &remaining_pubkeys,
    )
    .unwrap();

    assert_eq!(result.directly_revoked, member_b_fp);
    assert!(result.master_key_rotated);
    let new_cipher = new_cipher_opt.expect("should have rotated master key");

    // 4. Verify new master key works for owner and member A
    let owner_new_mk = unseal_master_key(&header, &owner_key, vault_id).unwrap();
    let member_a_new_mk = unseal_master_key(&header, &member_a_key, vault_id).unwrap();
    assert_eq!(owner_new_mk, *new_cipher.key_bytes());
    assert_eq!(member_a_new_mk, *new_cipher.key_bytes());

    // 5. Verify member B cannot unseal with the new header
    assert!(unseal_master_key(&header, &member_b_key, vault_id).is_err());

    // 6. Verify secrets can be re-encrypted with the new cipher
    // Decrypt with old cipher, then re-encrypt with new cipher
    let decrypted = decrypt_env(&encrypted_before, &original_cipher).unwrap();
    let re_encrypted = encrypt_env(&decrypted, &new_cipher, "dev").unwrap();

    // New cipher can decrypt
    let final_decrypted = decrypt_env(&re_encrypted, &new_cipher).unwrap();
    assert_eq!(
        final_decrypted.get("DB_URL").unwrap().value,
        SecretValue::String("postgres://localhost".into())
    );
    assert_eq!(
        final_decrypted.get("API_KEY").unwrap().value,
        SecretValue::String("sk-secret-123".into())
    );

    // Old cipher cannot decrypt re-encrypted data
    assert!(decrypt_env(&re_encrypted, &original_cipher).is_err());
}

#[test]
fn test_cascade_revocation_removes_delegatee_chain() {
    let vault_id = Uuid::new_v4();

    let owner_key = X25519PrivateKey::generate();
    let manager_key = X25519PrivateKey::generate();
    let child_key = X25519PrivateKey::generate();
    let grandchild_key = X25519PrivateKey::generate();

    let owner_fp = owner_key.public_key().fingerprint();
    let manager_fp = manager_key.public_key().fingerprint();
    let child_fp = child_key.public_key().fingerprint();
    let grandchild_fp = grandchild_key.public_key().fingerprint();

    let master_key = [0xCDu8; 32];
    let mut header = seal_master_key(
        &master_key,
        &[
            owner_key.public_key(),
            manager_key.public_key(),
            child_key.public_key(),
            grandchild_key.public_key(),
        ],
        vault_id,
    )
    .unwrap();

    let mut policy = VaultPolicy::new();
    policy.add_member(make_member(manager_fp.clone(), Role::Manager, None));
    policy.add_member(make_member(
        child_fp.clone(),
        Role::Contributor,
        Some(manager_fp.clone()),
    ));
    policy.add_member(make_member(
        grandchild_fp.clone(),
        Role::ReadOnly,
        Some(child_fp.clone()),
    ));

    let remaining = vec![
        (owner_fp.clone(), owner_key.public_key()),
        (manager_fp.clone(), manager_key.public_key()),
        (child_fp.clone(), child_key.public_key()),
        (grandchild_fp.clone(), grandchild_key.public_key()),
    ];

    // Revoke the manager with cascade - should also revoke child and grandchild
    let (result, _) = revoke_member(
        &manager_fp,
        true,
        &mut policy,
        &mut header,
        vault_id,
        &remaining,
    )
    .unwrap();

    assert_eq!(result.directly_revoked, manager_fp);
    assert_eq!(result.cascade_revoked.len(), 2);
    assert!(result.cascade_revoked.contains(&child_fp));
    assert!(result.cascade_revoked.contains(&grandchild_fp));

    // Only owner slot remains
    assert_eq!(header.slots.len(), 1);

    // Only owner can unseal
    assert!(unseal_master_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_master_key(&header, &manager_key, vault_id).is_err());
    assert!(unseal_master_key(&header, &child_key, vault_id).is_err());
    assert!(unseal_master_key(&header, &grandchild_key, vault_id).is_err());

    // All three removed from policy
    assert!(policy.get_member(&manager_fp).is_none());
    assert!(policy.get_member(&child_fp).is_none());
    assert!(policy.get_member(&grandchild_fp).is_none());
}

#[test]
fn test_revoke_without_cascade_preserves_children() {
    let vault_id = Uuid::new_v4();

    let owner_key = X25519PrivateKey::generate();
    let parent_key = X25519PrivateKey::generate();
    let child_key = X25519PrivateKey::generate();

    let owner_fp = owner_key.public_key().fingerprint();
    let parent_fp = parent_key.public_key().fingerprint();
    let child_fp = child_key.public_key().fingerprint();

    let master_key = [0xEFu8; 32];
    let mut header = seal_master_key(
        &master_key,
        &[
            owner_key.public_key(),
            parent_key.public_key(),
            child_key.public_key(),
        ],
        vault_id,
    )
    .unwrap();

    let mut policy = VaultPolicy::new();
    policy.add_member(make_member(parent_fp.clone(), Role::Manager, None));
    policy.add_member(make_member(
        child_fp.clone(),
        Role::ReadOnly,
        Some(parent_fp.clone()),
    ));

    let remaining = vec![
        (owner_fp.clone(), owner_key.public_key()),
        (parent_fp.clone(), parent_key.public_key()),
        (child_fp.clone(), child_key.public_key()),
    ];

    // Revoke parent WITHOUT cascade
    let (result, _) = revoke_member(
        &parent_fp,
        false,
        &mut policy,
        &mut header,
        vault_id,
        &remaining,
    )
    .unwrap();

    assert!(result.cascade_revoked.is_empty());

    // Parent removed from policy
    assert!(policy.get_member(&parent_fp).is_none());
    // Child still in policy
    assert!(policy.get_member(&child_fp).is_some());

    // Header has owner + child slots (parent excluded by revoke_member logic)
    assert_eq!(header.slots.len(), 2);
    assert!(unseal_master_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_master_key(&header, &child_key, vault_id).is_ok());
    assert!(unseal_master_key(&header, &parent_key, vault_id).is_err());
}
