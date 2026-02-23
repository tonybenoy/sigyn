use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::env_file::{decrypt_env, encrypt_env, PlaintextEnv};

fn roundtrip_secret(key: &str, value: SecretValue) {
    let cipher = VaultCipher::generate();
    let fp = KeyFingerprint([0xAAu8; 16]);

    let mut env = PlaintextEnv::new();
    env.set(key.into(), value.clone(), &fp);

    let encrypted = encrypt_env(&env, &cipher, "test").unwrap();
    let decrypted = decrypt_env(&encrypted, &cipher).unwrap();

    assert_eq!(decrypted.len(), 1);
    let recovered = &decrypted.get(key).unwrap().value;
    assert_eq!(*recovered, value);
}

#[test]
fn test_string_secret_roundtrip() {
    roundtrip_secret(
        "SIMPLE_STRING",
        SecretValue::String("hello-world-123".into()),
    );
}

#[test]
fn test_multiline_secret_roundtrip() {
    roundtrip_secret(
        "MULTILINE",
        SecretValue::Multiline("line1\nline2\nline3\n".into()),
    );
}

#[test]
fn test_json_secret_roundtrip() {
    let json_val = serde_json::json!({
        "host": "db.example.com",
        "port": 5432,
        "credentials": {
            "username": "admin",
            "password": "s3cret"
        },
        "options": ["ssl", "timeout=30"]
    });
    roundtrip_secret("JSON_CONFIG", SecretValue::Json(json_val));
}

#[test]
fn test_certificate_secret_roundtrip() {
    let cert = "-----BEGIN CERTIFICATE-----\n\
        MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw\n\
        DgYDVQQKEwdBY21lIENvMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFow\n\
        EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJxn\n\
        -----END CERTIFICATE-----";
    roundtrip_secret("TLS_CERT", SecretValue::Certificate(cert.into()));
}

#[test]
fn test_ssh_private_key_secret_roundtrip() {
    let ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
        QyNTUxOQAAACDFakeKeyDataHereForTestingPurposesOnlyAAAAAAAA\n\
        -----END OPENSSH PRIVATE KEY-----";
    roundtrip_secret("DEPLOY_KEY", SecretValue::SshPrivateKey(ssh_key.into()));
}

#[test]
fn test_file_secret_roundtrip() {
    let file_content = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG header bytes
    roundtrip_secret(
        "BINARY_FILE",
        SecretValue::File {
            name: "config.bin".into(),
            content: file_content,
        },
    );
}

#[test]
fn test_generated_secret_roundtrip() {
    roundtrip_secret(
        "GENERATED_TOKEN",
        SecretValue::Generated("aB3$xK9!mN2@pQ7&".into()),
    );
}

#[test]
fn test_reference_secret_roundtrip() {
    roundtrip_secret(
        "DB_URL_REF",
        SecretValue::Reference {
            vault: "shared-infra".into(),
            env: "prod".into(),
            key: "DATABASE_URL".into(),
        },
    );
}

#[test]
fn test_all_secret_types_in_single_env() {
    let cipher = VaultCipher::generate();
    let fp = KeyFingerprint([0xBBu8; 16]);

    let mut env = PlaintextEnv::new();
    env.set("S1".into(), SecretValue::String("plain".into()), &fp);
    env.set(
        "S2".into(),
        SecretValue::Multiline("a\nb\nc".into()),
        &fp,
    );
    env.set(
        "S3".into(),
        SecretValue::Json(serde_json::json!({"key": "val"})),
        &fp,
    );
    env.set(
        "S4".into(),
        SecretValue::Certificate("-----BEGIN CERT-----\ndata\n-----END CERT-----".into()),
        &fp,
    );
    env.set(
        "S5".into(),
        SecretValue::SshPrivateKey("-----BEGIN KEY-----\ndata\n-----END KEY-----".into()),
        &fp,
    );
    env.set(
        "S6".into(),
        SecretValue::File {
            name: "test.dat".into(),
            content: vec![1, 2, 3, 4, 5],
        },
        &fp,
    );
    env.set("S7".into(), SecretValue::Generated("gen-token".into()), &fp);
    env.set(
        "S8".into(),
        SecretValue::Reference {
            vault: "v".into(),
            env: "e".into(),
            key: "k".into(),
        },
        &fp,
    );

    let encrypted = encrypt_env(&env, &cipher, "mixed").unwrap();
    let decrypted = decrypt_env(&encrypted, &cipher).unwrap();

    assert_eq!(decrypted.len(), 8);
    assert_eq!(
        decrypted.get("S1").unwrap().value,
        SecretValue::String("plain".into())
    );
    assert_eq!(
        decrypted.get("S3").unwrap().value,
        SecretValue::Json(serde_json::json!({"key": "val"}))
    );
    assert_eq!(
        decrypted.get("S6").unwrap().value,
        SecretValue::File {
            name: "test.dat".into(),
            content: vec![1, 2, 3, 4, 5]
        }
    );
    assert_eq!(
        decrypted.get("S8").unwrap().value,
        SecretValue::Reference {
            vault: "v".into(),
            env: "e".into(),
            key: "k".into()
        }
    );
}

#[test]
fn test_empty_string_secret_roundtrip() {
    roundtrip_secret("EMPTY", SecretValue::String(String::new()));
}

#[test]
fn test_large_secret_roundtrip() {
    // 1 MB secret value
    let large_value = "x".repeat(1_000_000);
    roundtrip_secret("LARGE", SecretValue::String(large_value));
}
