use sigyn_engine::crypto::keys::{KeyFingerprint, SigningKeyPair};
use sigyn_engine::delegation::invite::InvitationFile;
use sigyn_engine::policy::roles::Role;

fn make_signed_invitation(
    vault_name: &str,
    role: Role,
    envs: &[&str],
    patterns: &[&str],
    depth: u32,
    kp: &SigningKeyPair,
) -> InvitationFile {
    let id = uuid::Uuid::new_v4();
    let vault_id = uuid::Uuid::new_v4();
    let fp = KeyFingerprint([0xAA; 16]);
    let envs: Vec<String> = envs.iter().map(|s| s.to_string()).collect();
    let patterns: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();

    let payload = InvitationFile::signing_payload(
        id, vault_name, vault_id, &fp, role, &envs, &patterns, depth,
    );
    let signature = kp.sign(&payload);

    InvitationFile {
        id,
        vault_name: vault_name.to_string(),
        vault_id,
        inviter_fingerprint: fp,
        proposed_role: role,
        allowed_envs: envs,
        secret_patterns: patterns,
        max_delegation_depth: depth,
        signature,
        created_at: chrono::Utc::now(),
        expires_at: None,
    }
}

#[test]
fn test_full_invitation_flow() {
    let kp = SigningKeyPair::generate();

    // Create invitation
    let invite = make_signed_invitation(
        "myapp",
        Role::Contributor,
        &["dev", "staging"],
        &["DB_*", "API_*"],
        2,
        &kp,
    );

    // Verify signature
    assert!(invite.verify(&kp.verifying_key()).is_ok());

    // Check fields
    assert_eq!(invite.vault_name, "myapp");
    assert_eq!(invite.proposed_role, Role::Contributor);
    assert_eq!(invite.allowed_envs, vec!["dev", "staging"]);
    assert_eq!(invite.secret_patterns, vec!["DB_*", "API_*"]);
    assert_eq!(invite.max_delegation_depth, 2);
}

#[test]
fn test_invitation_wrong_verifier() {
    let kp = SigningKeyPair::generate();
    let other_kp = SigningKeyPair::generate();

    let invite = make_signed_invitation("vault", Role::Admin, &["*"], &["*"], 5, &kp);

    // Correct key verifies
    assert!(invite.verify(&kp.verifying_key()).is_ok());

    // Wrong key fails
    assert!(invite.verify(&other_kp.verifying_key()).is_err());
}

#[test]
fn test_invitation_tampered_field() {
    let kp = SigningKeyPair::generate();

    let mut invite = make_signed_invitation("vault", Role::ReadOnly, &["dev"], &["*"], 1, &kp);

    // Tamper with a field after signing
    invite.proposed_role = Role::Owner;

    // Verification should fail because payload doesn't match signature
    assert!(invite.verify(&kp.verifying_key()).is_err());
}

#[test]
fn test_invitation_serialization_roundtrip() {
    let kp = SigningKeyPair::generate();

    let invite = make_signed_invitation(
        "vault",
        Role::Manager,
        &["dev", "prod"],
        &["SECRET_*"],
        3,
        &kp,
    );

    // Serialize to JSON
    let json = serde_json::to_string(&invite).unwrap();

    // Deserialize back
    let deserialized: InvitationFile = serde_json::from_str(&json).unwrap();

    // Signature should still verify after round-trip
    assert!(deserialized.verify(&kp.verifying_key()).is_ok());
    assert_eq!(deserialized.vault_name, "vault");
    assert_eq!(deserialized.proposed_role, Role::Manager);
}

#[test]
fn test_signing_payload_is_deterministic() {
    let id = uuid::Uuid::new_v4();
    let vault_id = uuid::Uuid::new_v4();
    let fp = KeyFingerprint([0xBB; 16]);
    let envs = vec!["dev".to_string()];
    let patterns = vec!["*".to_string()];

    let p1 =
        InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::Auditor, &envs, &patterns, 0);
    let p2 =
        InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::Auditor, &envs, &patterns, 0);

    assert_eq!(p1, p2);
}

#[test]
fn test_different_roles_produce_different_payloads() {
    let id = uuid::Uuid::new_v4();
    let vault_id = uuid::Uuid::new_v4();
    let fp = KeyFingerprint([0xCC; 16]);

    let p1 = InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::ReadOnly, &[], &[], 0);
    let p2 = InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::Owner, &[], &[], 0);

    assert_ne!(p1, p2);
}

#[test]
fn test_different_envs_produce_different_payloads() {
    let id = uuid::Uuid::new_v4();
    let vault_id = uuid::Uuid::new_v4();
    let fp = KeyFingerprint([0xDD; 16]);
    let envs_a = vec!["dev".to_string()];
    let envs_b = vec!["prod".to_string()];

    let p1 =
        InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::Contributor, &envs_a, &[], 0);
    let p2 =
        InvitationFile::signing_payload(id, "v", vault_id, &fp, Role::Contributor, &envs_b, &[], 0);

    assert_ne!(p1, p2);
}
