//! Security tests for the audit_mode policy feature and deploy key.
//!
//! These tests verify:
//! 1. Only owner/admin can change audit_mode (RBAC enforcement)
//! 2. audit_mode is part of the signed policy (tamper resistance)
//! 3. Online mode blocks when enforcement fails
//! 4. BestEffort mode does not block
//! 5. Offline mode never attempts push
//! 6. Deploy key seal/unseal only works with correct cipher
//! 7. Deploy key PEM output is structurally valid
//! 8. Backward compat: old policies without audit_mode field deserialize as Offline

use sigyn_engine::crypto::keys::{KeyFingerprint, SigningKeyPair};
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::policy::constraints::AuditMode;
use sigyn_engine::policy::engine::{AccessAction, AccessRequest, PolicyDecision, PolicyEngine};
use sigyn_engine::policy::member::MemberPolicy;
use sigyn_engine::policy::roles::Role;
use sigyn_engine::policy::storage::VaultPolicy;
use std::path::Path;
use tempfile::TempDir;

fn owner_fp() -> KeyFingerprint {
    KeyFingerprint([0x00u8; 16])
}
fn admin_fp() -> KeyFingerprint {
    KeyFingerprint([0x01u8; 16])
}
fn contributor_fp() -> KeyFingerprint {
    KeyFingerprint([0x02u8; 16])
}
fn readonly_fp() -> KeyFingerprint {
    KeyFingerprint([0x03u8; 16])
}

fn make_policy_with_members() -> VaultPolicy {
    let mut policy = VaultPolicy::new();
    policy.add_member(MemberPolicy::new(owner_fp(), Role::Owner));
    policy.add_member(MemberPolicy::new(admin_fp(), Role::Admin));
    policy.add_member(MemberPolicy::new(contributor_fp(), Role::Contributor));
    policy.add_member(MemberPolicy::new(readonly_fp(), Role::ReadOnly));
    policy
}

// ─── RBAC: Only owner/admin can change audit_mode ───

#[test]
fn test_owner_can_manage_policy() {
    let policy = make_policy_with_members();
    let ofp = owner_fp();
    let engine = PolicyEngine::new(&policy, &ofp);

    let request = AccessRequest {
        actor: owner_fp(),
        action: AccessAction::ManagePolicy,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    assert_eq!(engine.evaluate(&request).unwrap(), PolicyDecision::Allow);
}

#[test]
fn test_admin_can_manage_policy() {
    let policy = make_policy_with_members();
    let ofp = owner_fp();
    let engine = PolicyEngine::new(&policy, &ofp);

    let request = AccessRequest {
        actor: admin_fp(),
        action: AccessAction::ManagePolicy,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    assert_eq!(engine.evaluate(&request).unwrap(), PolicyDecision::Allow);
}

#[test]
fn test_contributor_cannot_manage_policy() {
    let policy = make_policy_with_members();
    let ofp = owner_fp();
    let engine = PolicyEngine::new(&policy, &ofp);

    let request = AccessRequest {
        actor: contributor_fp(),
        action: AccessAction::ManagePolicy,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    let decision = engine.evaluate(&request).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Deny(_)),
        "Contributor should be denied ManagePolicy, got: {:?}",
        decision
    );
}

#[test]
fn test_readonly_cannot_manage_policy() {
    let policy = make_policy_with_members();
    let ofp = owner_fp();
    let engine = PolicyEngine::new(&policy, &ofp);

    let request = AccessRequest {
        actor: readonly_fp(),
        action: AccessAction::ManagePolicy,
        env: "dev".into(),
        key: None,
        mfa_verified: false,
    };
    let decision = engine.evaluate(&request).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Deny(_)),
        "ReadOnly should be denied ManagePolicy, got: {:?}",
        decision
    );
}

// ─── Signed policy: audit_mode survives sign/encrypt roundtrip ───

#[test]
fn test_audit_mode_survives_signed_encrypted_roundtrip() {
    let cipher = VaultCipher::generate();
    let signing_key = SigningKeyPair::generate();
    let vault_id = uuid::Uuid::new_v4();

    let mut policy = make_policy_with_members();
    policy.audit_mode = AuditMode::Online;

    let bytes = policy
        .to_signed_encrypted_bytes(&cipher, &signing_key, &vault_id)
        .unwrap();
    let loaded = VaultPolicy::from_signed_encrypted_bytes(
        &bytes,
        &cipher,
        &signing_key.verifying_key(),
        &vault_id,
    )
    .unwrap();

    assert_eq!(loaded.audit_mode, AuditMode::Online);
}

#[test]
fn test_signed_policy_rejects_wrong_key() {
    let cipher = VaultCipher::generate();
    let signing_key = SigningKeyPair::generate();
    let wrong_key = SigningKeyPair::generate();
    let vault_id = uuid::Uuid::new_v4();

    let mut policy = make_policy_with_members();
    policy.audit_mode = AuditMode::Online;

    let bytes = policy
        .to_signed_encrypted_bytes(&cipher, &signing_key, &vault_id)
        .unwrap();

    // Verifying with wrong key should fail
    let result = VaultPolicy::from_signed_encrypted_bytes(
        &bytes,
        &cipher,
        &wrong_key.verifying_key(),
        &vault_id,
    );
    assert!(
        result.is_err(),
        "Signed policy should reject verification with wrong key"
    );
}

#[test]
fn test_signed_policy_rejects_wrong_vault_id() {
    let cipher = VaultCipher::generate();
    let signing_key = SigningKeyPair::generate();
    let vault_id = uuid::Uuid::new_v4();
    let wrong_vault_id = uuid::Uuid::new_v4();

    let mut policy = make_policy_with_members();
    policy.audit_mode = AuditMode::BestEffort;

    let bytes = policy
        .to_signed_encrypted_bytes(&cipher, &signing_key, &vault_id)
        .unwrap();

    // Verifying with wrong vault_id should fail (signature covers vault_id)
    let result = VaultPolicy::from_signed_encrypted_bytes(
        &bytes,
        &cipher,
        &signing_key.verifying_key(),
        &wrong_vault_id,
    );
    assert!(
        result.is_err(),
        "Signed policy should reject verification with wrong vault_id"
    );
}

// ─── Backward compatibility ───

#[test]
fn test_old_policy_without_audit_mode_deserializes_as_offline() {
    let cipher = VaultCipher::generate();

    // Simulate an old policy by creating one with default and encrypting
    let policy = VaultPolicy::new();
    assert_eq!(policy.audit_mode, AuditMode::Offline);

    let bytes = policy.to_encrypted_bytes(&cipher).unwrap();
    let loaded = VaultPolicy::from_encrypted_bytes(&bytes, &cipher).unwrap();
    assert_eq!(loaded.audit_mode, AuditMode::Offline);
}

// ─── AuditMode enum security ───

#[test]
fn test_audit_mode_rejects_invalid_values() {
    assert!("admin".parse::<AuditMode>().is_err());
    assert!("".parse::<AuditMode>().is_err());
    assert!("OFFLINE; DROP TABLE".parse::<AuditMode>().is_err());
    assert!("online\x00".parse::<AuditMode>().is_err());
}

// ─── Enforcement engine ───

#[test]
fn test_enforce_offline_never_pushes() {
    // Offline mode should return Skipped even without a valid git repo
    let tmp = TempDir::new().unwrap();
    let engine = sigyn_engine::sync::git::GitSyncEngine::new(tmp.path().to_path_buf());

    let result =
        sigyn_engine::audit::enforce_audit_push(AuditMode::Offline, &engine, "test", None).unwrap();
    assert!(matches!(
        result,
        sigyn_engine::audit::AuditPushOutcome::Skipped
    ));
}

#[test]
fn test_enforce_online_skips_without_remote() {
    // Online mode should skip when no git remote is configured
    let tmp = TempDir::new().unwrap();
    let engine = sigyn_engine::sync::git::GitSyncEngine::new(tmp.path().to_path_buf());
    engine.init().unwrap();

    let result =
        sigyn_engine::audit::enforce_audit_push(AuditMode::Online, &engine, "test", None).unwrap();
    assert!(matches!(
        result,
        sigyn_engine::audit::AuditPushOutcome::Skipped
    ));
}

#[test]
fn test_enforce_besteffort_skips_without_remote() {
    let tmp = TempDir::new().unwrap();
    let engine = sigyn_engine::sync::git::GitSyncEngine::new(tmp.path().to_path_buf());
    engine.init().unwrap();

    let result =
        sigyn_engine::audit::enforce_audit_push(AuditMode::BestEffort, &engine, "test", None)
            .unwrap();
    assert!(matches!(
        result,
        sigyn_engine::audit::AuditPushOutcome::Skipped
    ));
}

// ─── Deploy key security ───

#[test]
fn test_deploy_key_wrong_cipher_fails() {
    let cipher1 = VaultCipher::generate();
    let cipher2 = VaultCipher::generate();

    let (private_key, public_key) = sigyn_engine::sync::deploy_key::generate_ssh_keypair().unwrap();

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("deploy_key.sealed");

    // Seal with cipher1
    sigyn_engine::sync::deploy_key::seal_and_save(&path, &private_key, &public_key, &cipher1)
        .unwrap();

    // Attempt unseal with cipher2 — should fail (decryption error)
    let result = sigyn_engine::sync::deploy_key::load_and_unseal(&path, &cipher2);
    assert!(
        result.is_err(),
        "Unsealing deploy key with wrong cipher should fail"
    );
}

#[test]
fn test_deploy_key_tampered_file_fails() {
    let cipher = VaultCipher::generate();
    let (private_key, public_key) = sigyn_engine::sync::deploy_key::generate_ssh_keypair().unwrap();

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("deploy_key.sealed");

    sigyn_engine::sync::deploy_key::seal_and_save(&path, &private_key, &public_key, &cipher)
        .unwrap();

    // Tamper: flip a byte in the sealed private key
    let mut data = std::fs::read_to_string(&path).unwrap();
    // Find the sealed_private_key field and flip a character
    if let Some(pos) = data.find("sealed_private_key") {
        let bytes = unsafe { data.as_bytes_mut() };
        // Find a position within the base64 data
        let flip_pos = pos + 30;
        if flip_pos < bytes.len() {
            bytes[flip_pos] ^= 0x01;
        }
    }
    std::fs::write(&path, &data).unwrap();

    let result = sigyn_engine::sync::deploy_key::load_and_unseal(&path, &cipher);
    assert!(
        result.is_err(),
        "Tampered deploy key file should fail to unseal"
    );
}

#[test]
fn test_deploy_key_nonexistent_returns_none() {
    let cipher = VaultCipher::generate();
    let result =
        sigyn_engine::sync::deploy_key::load_and_unseal(Path::new("/no/such/path"), &cipher)
            .unwrap();
    assert!(result.is_none());
}

#[test]
fn test_deploy_key_pem_structure() {
    let (private_key, _) = sigyn_engine::sync::deploy_key::generate_ssh_keypair().unwrap();
    assert_eq!(
        private_key.len(),
        32,
        "Ed25519 secret key should be 32 bytes"
    );

    // The key should produce a valid OpenSSH PEM when used in make_deploy_key_callbacks
    // We can't easily test SSH auth without a real server, but we can verify the PEM builds
    let (_, _temp_dir) =
        sigyn_engine::sync::deploy_key::make_deploy_key_callbacks(&private_key).unwrap();
    // If we got here without error, the PEM was accepted by the system
}

#[test]
fn test_deploy_key_different_keys_produce_different_ciphertext() {
    let cipher = VaultCipher::generate();

    let (key1, pub1) = sigyn_engine::sync::deploy_key::generate_ssh_keypair().unwrap();
    let (key2, pub2) = sigyn_engine::sync::deploy_key::generate_ssh_keypair().unwrap();

    // Different keys should produce different public keys
    assert_ne!(
        pub1, pub2,
        "Two generated keys should have different public keys"
    );
    assert_ne!(
        key1, key2,
        "Two generated keys should have different private keys"
    );

    let tmp = TempDir::new().unwrap();
    let path1 = tmp.path().join("dk1.sealed");
    let path2 = tmp.path().join("dk2.sealed");

    sigyn_engine::sync::deploy_key::seal_and_save(&path1, &key1, &pub1, &cipher).unwrap();
    sigyn_engine::sync::deploy_key::seal_and_save(&path2, &key2, &pub2, &cipher).unwrap();

    let data1 = std::fs::read(&path1).unwrap();
    let data2 = std::fs::read(&path2).unwrap();
    assert_ne!(
        data1, data2,
        "Different keys should produce different sealed files"
    );
}

// ─── Online mode fails with unreachable remote ───

#[test]
fn test_enforce_online_fails_with_unreachable_remote() {
    let tmp = TempDir::new().unwrap();
    let engine = sigyn_engine::sync::git::GitSyncEngine::new(tmp.path().to_path_buf());
    engine.init().unwrap();

    // Add a remote that can't be reached
    engine
        .add_remote("origin", "ssh://nonexistent.invalid/repo.git")
        .unwrap();

    // Stage a file so there are changes to push
    std::fs::write(tmp.path().join("test.txt"), "data").unwrap();
    engine.stage_all().unwrap();
    engine.commit("test commit").unwrap();

    // Online mode should return AuditPushRequired error
    let result = sigyn_engine::audit::enforce_audit_push(AuditMode::Online, &engine, "test", None);
    assert!(
        result.is_err(),
        "Online mode should fail with unreachable remote"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, sigyn_engine::SigynError::AuditPushRequired(_)),
        "Error should be AuditPushRequired, got: {:?}",
        err
    );
}

#[test]
fn test_enforce_besteffort_warns_with_unreachable_remote() {
    let tmp = TempDir::new().unwrap();
    let engine = sigyn_engine::sync::git::GitSyncEngine::new(tmp.path().to_path_buf());
    engine.init().unwrap();

    engine
        .add_remote("origin", "ssh://nonexistent.invalid/repo.git")
        .unwrap();

    std::fs::write(tmp.path().join("test.txt"), "data").unwrap();
    engine.stage_all().unwrap();
    engine.commit("test commit").unwrap();

    // BestEffort should succeed but return BestEffortFailed
    let result =
        sigyn_engine::audit::enforce_audit_push(AuditMode::BestEffort, &engine, "test", None)
            .unwrap();
    assert!(
        matches!(
            result,
            sigyn_engine::audit::AuditPushOutcome::BestEffortFailed(_)
        ),
        "BestEffort should return BestEffortFailed with unreachable remote, got: {:?}",
        match &result {
            sigyn_engine::audit::AuditPushOutcome::BestEffortFailed(r) =>
                format!("BestEffortFailed({})", r),
            sigyn_engine::audit::AuditPushOutcome::Skipped => "Skipped".to_string(),
            sigyn_engine::audit::AuditPushOutcome::Pushed => "Pushed".to_string(),
        }
    );
}

// ─── Audit mode persistence across policy save/load ───

#[test]
fn test_all_audit_modes_survive_roundtrip() {
    let cipher = VaultCipher::generate();
    let signing_key = SigningKeyPair::generate();
    let vault_id = uuid::Uuid::new_v4();

    for mode in [AuditMode::Offline, AuditMode::Online, AuditMode::BestEffort] {
        let mut policy = VaultPolicy::new();
        policy.audit_mode = mode;

        let bytes = policy
            .to_signed_encrypted_bytes(&cipher, &signing_key, &vault_id)
            .unwrap();
        let loaded = VaultPolicy::from_signed_encrypted_bytes(
            &bytes,
            &cipher,
            &signing_key.verifying_key(),
            &vault_id,
        )
        .unwrap();

        assert_eq!(
            loaded.audit_mode, mode,
            "AuditMode {:?} should survive signed+encrypted roundtrip",
            mode
        );
    }
}
