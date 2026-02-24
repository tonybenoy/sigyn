use sigyn_core::crypto::envelope::{add_recipient, seal_master_key, unseal_master_key};
use sigyn_core::crypto::keys::{KeyFingerprint, X25519PrivateKey};
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::policy::engine::{AccessAction, AccessRequest, PolicyDecision, PolicyEngine};
use sigyn_core::policy::member::MemberPolicy;
use sigyn_core::policy::roles::Role;
use sigyn_core::policy::storage::VaultPolicy;
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::env_file::{decrypt_env, encrypt_env, PlaintextEnv};
use uuid::Uuid;

#[test]
fn test_multi_member_access() {
    let vault_id = Uuid::new_v4();

    // 1. Create owner identity + vault
    let owner_key = X25519PrivateKey::generate();
    let owner_pub = owner_key.public_key();
    let owner_fp = owner_pub.fingerprint();

    // Generate a master key and seal it for the owner
    let master_key = [0xABu8; 32];
    let mut header = seal_master_key(&master_key, &[owner_pub.clone()], vault_id).unwrap();

    // Owner can unseal
    let recovered_owner = unseal_master_key(&header, &owner_key, vault_id).unwrap();
    assert_eq!(master_key, recovered_owner);

    // 2. Create member identity
    let member_key = X25519PrivateKey::generate();
    let member_pub = member_key.public_key();
    let member_fp = member_pub.fingerprint();

    // 3. Add member to envelope header
    add_recipient(&mut header, &master_key, &member_pub, vault_id).unwrap();
    assert_eq!(header.slots.len(), 2);

    // 4. Add member to policy with ReadOnly role
    let mut policy = VaultPolicy::new();
    policy.add_member(MemberPolicy::new(member_fp.clone(), Role::ReadOnly));

    let engine = PolicyEngine::new(&policy, &owner_fp);

    // 5. Verify member can unseal master key
    let recovered_member = unseal_master_key(&header, &member_key, vault_id).unwrap();
    assert_eq!(master_key, recovered_member);

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

    let master_key = [0xFFu8; 32];
    let mut header = seal_master_key(&master_key, &[owner_key.public_key()], vault_id).unwrap();

    // Add member to envelope
    add_recipient(&mut header, &master_key, &member_key.public_key(), vault_id).unwrap();

    // Create and encrypt secrets
    let cipher = VaultCipher::new(master_key);
    let fp = owner_key.public_key().fingerprint();
    let mut env = PlaintextEnv::new();
    env.set(
        "SECRET_KEY".into(),
        SecretValue::String("super-secret-value".into()),
        &fp,
    );

    let encrypted = encrypt_env(&env, &cipher, "dev").unwrap();

    // Member unseals the master key and creates their own cipher to decrypt
    let member_mk = unseal_master_key(&header, &member_key, vault_id).unwrap();
    assert_eq!(member_mk, master_key);

    let member_cipher = VaultCipher::new(member_mk);
    let decrypted = decrypt_env(&encrypted, &member_cipher).unwrap();
    assert_eq!(
        decrypted.get("SECRET_KEY").unwrap().value,
        SecretValue::String("super-secret-value".into())
    );
}
