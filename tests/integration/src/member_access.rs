use std::collections::BTreeMap;

use sigyn_engine::crypto::envelope::{
    add_vault_key_recipient, seal_v2, unseal_env_key, unseal_vault_key,
};
use sigyn_engine::crypto::keys::{KeyFingerprint, X25519PrivateKey};
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::policy::engine::{AccessAction, AccessRequest, PolicyDecision, PolicyEngine};
use sigyn_engine::policy::member::MemberPolicy;
use sigyn_engine::policy::roles::Role;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::env_file::{decrypt_env, encrypt_env, PlaintextEnv};
use uuid::Uuid;

#[test]
fn test_multi_member_access() {
    let vault_id = Uuid::new_v4();

    // 1. Create owner identity + vault
    let owner_key = X25519PrivateKey::generate();
    let owner_pub = owner_key.public_key();
    let owner_fp = owner_pub.fingerprint();

    // Generate keys and seal for the owner
    let vault_key = [0xABu8; 32];
    let dev_key = [0xBBu8; 32];

    let mut env_keys = BTreeMap::new();
    env_keys.insert("dev".to_string(), dev_key);
    let mut env_recipients = BTreeMap::new();
    env_recipients.insert("dev".to_string(), vec![owner_pub.clone()]);

    let mut header = seal_v2(
        &vault_key,
        &env_keys,
        &[owner_pub.clone()],
        &env_recipients,
        vault_id,
    )
    .unwrap();

    // Owner can unseal
    let recovered_owner = unseal_vault_key(&header, &owner_key, vault_id).unwrap();
    assert_eq!(vault_key, recovered_owner);

    // 2. Create member identity
    let member_key = X25519PrivateKey::generate();
    let member_pub = member_key.public_key();
    let member_fp = member_pub.fingerprint();

    // 3. Add member to envelope header (vault key only — they get env access separately)
    add_vault_key_recipient(&mut header, &vault_key, &member_pub, vault_id).unwrap();
    assert_eq!(header.vault_key_slots.len(), 2);

    // 4. Add member to policy with ReadOnly role
    let mut policy = VaultPolicy::new();
    policy.add_member(MemberPolicy::new(member_fp.clone(), Role::ReadOnly));

    let engine = PolicyEngine::new(&policy, &owner_fp);

    // 5. Verify member can unseal vault key
    let recovered_member = unseal_vault_key(&header, &member_key, vault_id).unwrap();
    assert_eq!(vault_key, recovered_member);

    // 6. Verify member can read secrets (policy engine returns Allow)
    let read_request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Read,
        env: "dev".into(),
        key: Some("DATABASE_URL".into()),
        mfa_verified: false,
    };
    assert_eq!(
        engine.evaluate(&read_request).unwrap(),
        PolicyDecision::Allow
    );

    // 7. Verify member cannot write (policy engine returns Deny)
    let write_request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Write,
        env: "dev".into(),
        key: Some("DATABASE_URL".into()),
        mfa_verified: false,
    };
    assert!(matches!(
        engine.evaluate(&write_request).unwrap(),
        PolicyDecision::Deny(_)
    ));

    // 8. Verify member cannot delete
    let delete_request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Delete,
        env: "dev".into(),
        key: Some("DATABASE_URL".into()),
        mfa_verified: false,
    };
    assert!(matches!(
        engine.evaluate(&delete_request).unwrap(),
        PolicyDecision::Deny(_)
    ));

    // 9. Verify member cannot manage members
    let manage_request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::ManageMembers,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    assert!(matches!(
        engine.evaluate(&manage_request).unwrap(),
        PolicyDecision::Deny(_)
    ));

    // 10. Verify the owner always gets Allow for all actions
    for action in [
        AccessAction::Read,
        AccessAction::Write,
        AccessAction::Delete,
        AccessAction::ManageMembers,
        AccessAction::ManagePolicy,
        AccessAction::CreateEnv,
        AccessAction::Promote,
    ] {
        let owner_request = AccessRequest {
            actor: owner_fp.clone(),
            action,
            env: "prod".into(),
            key: Some("ANYTHING".into()),
            mfa_verified: false,
        };
        assert_eq!(
            engine.evaluate(&owner_request).unwrap(),
            PolicyDecision::Allow,
        );
    }
}

#[test]
fn test_contributor_can_read_and_write() {
    let owner_fp = KeyFingerprint([0u8; 16]);
    let contributor_fp = KeyFingerprint([1u8; 16]);

    let mut policy = VaultPolicy::new();
    policy.add_member(MemberPolicy::new(contributor_fp.clone(), Role::Contributor));

    let engine = PolicyEngine::new(&policy, &owner_fp);

    // Contributor can read
    let read_req = AccessRequest {
        actor: contributor_fp.clone(),
        action: AccessAction::Read,
        env: "dev".into(),
        key: Some("API_KEY".into()),
        mfa_verified: false,
    };
    assert_eq!(engine.evaluate(&read_req).unwrap(), PolicyDecision::Allow);

    // Contributor can write
    let write_req = AccessRequest {
        actor: contributor_fp.clone(),
        action: AccessAction::Write,
        env: "dev".into(),
        key: Some("API_KEY".into()),
        mfa_verified: false,
    };
    assert_eq!(engine.evaluate(&write_req).unwrap(), PolicyDecision::Allow);

    // Contributor cannot manage members
    let manage_req = AccessRequest {
        actor: contributor_fp.clone(),
        action: AccessAction::ManageMembers,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    assert!(matches!(
        engine.evaluate(&manage_req).unwrap(),
        PolicyDecision::Deny(_)
    ));
}

#[test]
fn test_env_restriction() {
    let owner_fp = KeyFingerprint([0u8; 16]);
    let member_fp = KeyFingerprint([1u8; 16]);

    let mut policy = VaultPolicy::new();
    let mut member = MemberPolicy::new(member_fp.clone(), Role::Contributor);
    // Restrict to only dev environment
    member.allowed_envs = vec!["dev".into()];
    policy.add_member(member);

    let engine = PolicyEngine::new(&policy, &owner_fp);

    // Can access dev
    let dev_req = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Read,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    assert_eq!(engine.evaluate(&dev_req).unwrap(), PolicyDecision::Allow);

    // Cannot access prod
    let prod_req = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Read,
        env: "prod".into(),
        key: None,
        mfa_verified: false,
    };
    assert!(matches!(
        engine.evaluate(&prod_req).unwrap(),
        PolicyDecision::Deny(_)
    ));
}

#[test]
fn test_member_can_decrypt_actual_secrets() {
    let vault_id = Uuid::new_v4();
    let owner_key = X25519PrivateKey::generate();
    let member_key = X25519PrivateKey::generate();

    let vault_key = [0xFFu8; 32];
    let dev_key = [0xEEu8; 32];

    let mut env_keys = BTreeMap::new();
    env_keys.insert("dev".to_string(), dev_key);
    let mut env_recipients = BTreeMap::new();
    env_recipients.insert(
        "dev".to_string(),
        vec![owner_key.public_key(), member_key.public_key()],
    );

    let header = seal_v2(
        &vault_key,
        &env_keys,
        &[owner_key.public_key(), member_key.public_key()],
        &env_recipients,
        vault_id,
    )
    .unwrap();

    // Create and encrypt secrets with the env key
    let cipher = VaultCipher::new(dev_key);
    let fp = owner_key.public_key().fingerprint();
    let mut env = PlaintextEnv::new();
    env.set(
        "SECRET_KEY".into(),
        SecretValue::String("super-secret-value".into()),
        &fp,
    );

    let encrypted = encrypt_env(&env, &cipher, "dev").unwrap();

    // Member unseals the env key and creates their own cipher to decrypt
    let member_dev = unseal_env_key(&header, "dev", &member_key, vault_id).unwrap();
    assert_eq!(member_dev, dev_key);

    let member_cipher = VaultCipher::new(member_dev);
    let decrypted = decrypt_env(&encrypted, &member_cipher).unwrap();
    assert_eq!(
        decrypted.get("SECRET_KEY").unwrap().value,
        SecretValue::String("super-secret-value".into())
    );
}
