use std::collections::BTreeMap;

use sigyn_engine::crypto::envelope::{seal_v2, unseal_env_key, unseal_vault_key};
use sigyn_engine::crypto::keys::{KeyFingerprint, X25519PrivateKey};
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::delegation::revoke::revoke_member;
use sigyn_engine::policy::member::MemberPolicy;
use sigyn_engine::policy::roles::Role;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::env_file::{decrypt_env, encrypt_env, PlaintextEnv};
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

    // Build v2 header with per-env keys
    let vault_key = [0xABu8; 32];
    let dev_key = [0xBBu8; 32];

    let mut env_keys = BTreeMap::new();
    env_keys.insert("dev".to_string(), dev_key);

    let all_pubs = vec![
        owner_key.public_key(),
        member_a_key.public_key(),
        member_b_key.public_key(),
    ];
    let mut env_recipients = BTreeMap::new();
    env_recipients.insert("dev".to_string(), all_pubs.clone());

    let mut header = seal_v2(&vault_key, &env_keys, &all_pubs, &env_recipients, vault_id).unwrap();
    assert_eq!(header.vault_key_slots.len(), 3);

    // Build policy: member B was delegated by owner (top-level), member A is independent
    let mut policy = VaultPolicy::new();
    let mut member_a = make_member(member_a_fp.clone(), Role::Contributor, None);
    member_a.allowed_envs = vec!["dev".into()];
    policy.add_member(member_a);
    let mut member_b = make_member(
        member_b_fp.clone(),
        Role::Contributor,
        Some(owner_fp.clone()),
    );
    member_b.allowed_envs = vec!["dev".into()];
    policy.add_member(member_b);

    // 2. Set secrets using the dev key
    let original_cipher = VaultCipher::new(dev_key);
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
    assert!(unseal_vault_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_vault_key(&header, &member_a_key, vault_id).is_ok());
    assert!(unseal_vault_key(&header, &member_b_key, vault_id).is_ok());

    // 3. Revoke member B with cascade
    let remaining_pubkeys = vec![
        (owner_fp.clone(), owner_key.public_key()),
        (member_a_fp.clone(), member_a_key.public_key()),
        (member_b_fp.clone(), member_b_key.public_key()),
    ];

    let mut member_env_access = BTreeMap::new();
    member_env_access.insert(owner_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(member_a_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(member_b_fp.clone(), vec!["dev".to_string()]);

    let (result,) = revoke_member(
        &member_b_fp,
        true,
        &mut policy,
        &mut header,
        vault_id,
        &remaining_pubkeys,
        &member_env_access,
    )
    .unwrap();

    assert_eq!(result.directly_revoked, member_b_fp);
    assert!(result.affected_envs.contains(&"dev".to_string()));

    // 4. Verify owner and member A can still unseal vault key
    assert!(unseal_vault_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_vault_key(&header, &member_a_key, vault_id).is_ok());

    // 5. Verify member B cannot unseal
    assert!(unseal_vault_key(&header, &member_b_key, vault_id).is_err());

    // 6. Verify dev env key was rotated and secrets can be re-encrypted
    let new_dev_cipher = result.rotated_env_ciphers.get("dev").unwrap();
    let decrypted = decrypt_env(&encrypted_before, &original_cipher).unwrap();
    let re_encrypted = encrypt_env(&decrypted, new_dev_cipher, "dev").unwrap();

    // New cipher can decrypt
    let final_decrypted = decrypt_env(&re_encrypted, new_dev_cipher).unwrap();
    assert_eq!(
        final_decrypted.get("DB_URL").unwrap().value,
        SecretValue::String("postgres://localhost".into())
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

    let vault_key = [0xCDu8; 32];
    let dev_key = [0xDDu8; 32];

    let all_pubs = vec![
        owner_key.public_key(),
        manager_key.public_key(),
        child_key.public_key(),
        grandchild_key.public_key(),
    ];

    let mut env_keys = BTreeMap::new();
    env_keys.insert("dev".to_string(), dev_key);
    let mut env_recipients = BTreeMap::new();
    env_recipients.insert("dev".to_string(), all_pubs.clone());

    let mut header = seal_v2(&vault_key, &env_keys, &all_pubs, &env_recipients, vault_id).unwrap();

    let mut policy = VaultPolicy::new();
    let mut mgr = make_member(manager_fp.clone(), Role::Manager, None);
    mgr.allowed_envs = vec!["dev".into()];
    policy.add_member(mgr);
    let mut child = make_member(
        child_fp.clone(),
        Role::Contributor,
        Some(manager_fp.clone()),
    );
    child.allowed_envs = vec!["dev".into()];
    policy.add_member(child);
    let mut gc = make_member(
        grandchild_fp.clone(),
        Role::ReadOnly,
        Some(child_fp.clone()),
    );
    gc.allowed_envs = vec!["dev".into()];
    policy.add_member(gc);

    let remaining = vec![
        (owner_fp.clone(), owner_key.public_key()),
        (manager_fp.clone(), manager_key.public_key()),
        (child_fp.clone(), child_key.public_key()),
        (grandchild_fp.clone(), grandchild_key.public_key()),
    ];

    let mut member_env_access = BTreeMap::new();
    member_env_access.insert(owner_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(manager_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(child_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(grandchild_fp.clone(), vec!["dev".to_string()]);

    // Revoke the manager with cascade - should also revoke child and grandchild
    let (result,) = revoke_member(
        &manager_fp,
        true,
        &mut policy,
        &mut header,
        vault_id,
        &remaining,
        &member_env_access,
    )
    .unwrap();

    assert_eq!(result.directly_revoked, manager_fp);
    assert_eq!(result.cascade_revoked.len(), 2);
    assert!(result.cascade_revoked.contains(&child_fp));
    assert!(result.cascade_revoked.contains(&grandchild_fp));

    // Only owner vault_key_slot remains
    assert_eq!(header.vault_key_slots.len(), 1);

    // Only owner can unseal
    assert!(unseal_vault_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_vault_key(&header, &manager_key, vault_id).is_err());
    assert!(unseal_vault_key(&header, &child_key, vault_id).is_err());
    assert!(unseal_vault_key(&header, &grandchild_key, vault_id).is_err());

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

    let vault_key = [0xEFu8; 32];
    let dev_key = [0xFFu8; 32];

    let all_pubs = vec![
        owner_key.public_key(),
        parent_key.public_key(),
        child_key.public_key(),
    ];

    let mut env_keys = BTreeMap::new();
    env_keys.insert("dev".to_string(), dev_key);
    let mut env_recipients = BTreeMap::new();
    env_recipients.insert("dev".to_string(), all_pubs.clone());

    let mut header = seal_v2(&vault_key, &env_keys, &all_pubs, &env_recipients, vault_id).unwrap();

    let mut policy = VaultPolicy::new();
    let mut p = make_member(parent_fp.clone(), Role::Manager, None);
    p.allowed_envs = vec!["dev".into()];
    policy.add_member(p);
    let mut c = make_member(child_fp.clone(), Role::ReadOnly, Some(parent_fp.clone()));
    c.allowed_envs = vec!["dev".into()];
    policy.add_member(c);

    let remaining = vec![
        (owner_fp.clone(), owner_key.public_key()),
        (parent_fp.clone(), parent_key.public_key()),
        (child_fp.clone(), child_key.public_key()),
    ];

    let mut member_env_access = BTreeMap::new();
    member_env_access.insert(owner_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(parent_fp.clone(), vec!["dev".to_string()]);
    member_env_access.insert(child_fp.clone(), vec!["dev".to_string()]);

    // Revoke parent WITHOUT cascade
    let (result,) = revoke_member(
        &parent_fp,
        false,
        &mut policy,
        &mut header,
        vault_id,
        &remaining,
        &member_env_access,
    )
    .unwrap();

    assert!(result.cascade_revoked.is_empty());

    // Parent removed from policy
    assert!(policy.get_member(&parent_fp).is_none());
    // Child still in policy
    assert!(policy.get_member(&child_fp).is_some());

    // Header has owner + child vault_key_slots (parent removed)
    assert_eq!(header.vault_key_slots.len(), 2);
    assert!(unseal_vault_key(&header, &owner_key, vault_id).is_ok());
    assert!(unseal_vault_key(&header, &child_key, vault_id).is_ok());
    assert!(unseal_vault_key(&header, &parent_key, vault_id).is_err());
}
