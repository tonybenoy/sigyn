use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const PASSPHRASE: &str = "test-pass-123";

/// Create a fresh SIGYN_HOME in a temp directory.
fn fresh_home() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn sigyn(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("sigyn").unwrap();
    cmd.env("SIGYN_HOME", home.path())
        .env("SIGYN_PASSPHRASE", PASSPHRASE)
        .env("NO_COLOR", "1");
    cmd
}

fn sigyn_home_path(home: &TempDir) -> PathBuf {
    home.path().to_path_buf()
}

// ─── Identity lifecycle ──────────────────────────────────────────────

#[test]
fn test_identity_create() {
    let home = fresh_home();
    sigyn(&home)
        .args(["identity", "create", "-n", "alice"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Identity 'alice' created"));
}

#[test]
fn test_identity_create_duplicate() {
    let home = fresh_home();
    sigyn(&home)
        .args(["identity", "create", "-n", "alice"])
        .assert()
        .success();

    sigyn(&home)
        .args(["identity", "create", "-n", "alice"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_identity_create_short_passphrase() {
    let home = fresh_home();
    let mut cmd = Command::cargo_bin("sigyn").unwrap();
    cmd.env("SIGYN_HOME", home.path())
        .env("SIGYN_PASSPHRASE", "short")
        .env("NO_COLOR", "1");
    cmd.args(["identity", "create", "-n", "alice"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least 8 characters"));
}

#[test]
fn test_identity_list_empty() {
    let home = fresh_home();
    sigyn(&home)
        .args(["identity", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No identities found"));
}

#[test]
fn test_identity_list_with_entries() {
    let home = fresh_home();
    sigyn(&home)
        .args(["identity", "create", "-n", "alice"])
        .assert()
        .success();

    sigyn(&home)
        .args(["identity", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));
}

#[test]
fn test_identity_show() {
    let home = fresh_home();
    sigyn(&home)
        .args([
            "identity",
            "create",
            "-n",
            "alice",
            "-E",
            "alice@example.com",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args(["identity", "show", "alice"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Name:")
                .and(predicate::str::contains("alice"))
                .and(predicate::str::contains("alice@example.com"))
                .and(predicate::str::contains("Fingerprint:")),
        );
}

#[test]
fn test_identity_show_not_found() {
    let home = fresh_home();
    sigyn(&home)
        .args(["identity", "show", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("identity not found"));
}

#[test]
fn test_identity_json_output() {
    let home = fresh_home();
    sigyn(&home)
        .args(["identity", "create", "-n", "alice"])
        .assert()
        .success();

    sigyn(&home)
        .args(["--json", "identity", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\""));
}

// ─── Vault lifecycle ──────────────────────────────────────────────

fn setup_identity(home: &TempDir) {
    sigyn(home)
        .args(["identity", "create", "-n", "testuser"])
        .assert()
        .success();
}

#[test]
fn test_vault_create() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault 'myapp' created"));
}

#[test]
fn test_vault_create_duplicate() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_vault_list_empty() {
    let home = fresh_home();
    sigyn(&home)
        .args(["vault", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No vaults found"));
}

#[test]
fn test_vault_list_with_entries() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args(["vault", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("myapp"));
}

#[test]
fn test_vault_info() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args(["vault", "info", "myapp"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("myapp")
                .and(predicate::str::contains("Environments"))
                .and(predicate::str::contains("dev")),
        );
}

#[test]
fn test_vault_info_json() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args(["--json", "vault", "info", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"vault_id\""));
}

#[test]
fn test_vault_info_not_found() {
    let home = fresh_home();
    sigyn(&home)
        .args(["vault", "info", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

// ─── Secret CRUD ──────────────────────────────────────────────

fn setup_vault(home: &TempDir) {
    setup_identity(home);
    sigyn(home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success();
}

#[test]
fn test_secret_set_and_get() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret",
            "set",
            "DB_URL",
            "postgres://localhost",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Set 'DB_URL'"));

    sigyn(&home)
        .args([
            "secret", "get", "DB_URL", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://localhost"));
}

#[test]
fn test_secret_update() {
    let home = fresh_home();
    setup_vault(&home);

    // Set initial value
    sigyn(&home)
        .args([
            "secret", "set", "KEY", "v1", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    // Update it
    sigyn(&home)
        .args([
            "secret", "set", "KEY", "v2", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated 'KEY'"));

    // Verify new value
    sigyn(&home)
        .args([
            "secret", "get", "KEY", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("v2"));
}

#[test]
fn test_secret_list() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "A", "1", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "secret", "set", "B", "2", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "secret", "list", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("A")
                .and(predicate::str::contains("B"))
                .and(predicate::str::contains("2 keys")),
        );
}

#[test]
fn test_secret_list_hidden_by_default() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret",
            "set",
            "SECRET",
            "sensitive-data",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    // Without --reveal, values should be masked
    sigyn(&home)
        .args([
            "secret", "list", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("••••••••"));
}

#[test]
fn test_secret_list_reveal() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret",
            "set",
            "SECRET",
            "sensitive-data",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    // With --reveal, values should be shown
    sigyn(&home)
        .args([
            "secret", "list", "--reveal", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("sensitive-data"));
}

#[test]
fn test_secret_remove() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "DEL_ME", "bye", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "secret", "remove", "DEL_ME", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed 'DEL_ME'"));

    // Should no longer exist
    sigyn(&home)
        .args([
            "secret", "get", "DEL_ME", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_secret_get_nonexistent() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "get", "NOPE", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_secret_generate() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "generate", "TOKEN", "--length", "16", "--type", "hex", "-v", "myapp", "-e",
            "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated 'TOKEN'"));

    // Verify it can be retrieved
    sigyn(&home)
        .args([
            "secret", "get", "TOKEN", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();
}

#[test]
fn test_secret_generate_types() {
    let home = fresh_home();
    setup_vault(&home);

    for gen_type in &["password", "uuid", "hex", "base64", "alphanumeric"] {
        let key = format!("KEY_{}", gen_type.to_uppercase());
        sigyn(&home)
            .args([
                "secret", "generate", &key, "--type", gen_type, "-v", "myapp", "-e", "dev", "-i",
                "testuser",
            ])
            .assert()
            .success();
    }
}

#[test]
fn test_secret_json_output() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "KEY", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "--json", "secret", "get", "KEY", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"key\"")
                .and(predicate::str::contains("\"value\""))
                .and(predicate::str::contains("\"type\"")),
        );
}

// ─── Environment management ──────────────────────────────────────

#[test]
fn test_env_list() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["env", "list", "-v", "myapp"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("dev")
                .and(predicate::str::contains("staging"))
                .and(predicate::str::contains("prod")),
        );
}

#[test]
fn test_env_create() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["env", "create", "testing", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created environment 'testing'"));

    // Verify it appears in list
    sigyn(&home)
        .args(["env", "list", "-v", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("testing"));
}

#[test]
fn test_env_create_duplicate() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["env", "create", "dev", "-v", "myapp", "-i", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_env_promote() {
    let home = fresh_home();
    setup_vault(&home);

    // Set a secret in dev
    sigyn(&home)
        .args([
            "secret", "set", "API_KEY", "dev-key", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    // Promote dev -> staging
    sigyn(&home)
        .args([
            "env", "promote", "--from", "dev", "--to", "staging", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Promoted"));

    // Verify secret exists in staging
    sigyn(&home)
        .args([
            "secret", "get", "API_KEY", "-v", "myapp", "-e", "staging", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev-key"));
}

// ─── Policy commands ─────────────────────────────────────────────

#[test]
fn test_policy_show_empty() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["policy", "show", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No additional members"));
}

#[test]
fn test_policy_show_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["--json", "policy", "show", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"owner\"").and(predicate::str::contains("\"members\"")));
}

// ─── Audit trail ─────────────────────────────────────────────────

#[test]
fn test_audit_tail() {
    let home = fresh_home();
    setup_vault(&home);

    // Audit log should have the vault creation entry
    sigyn(&home)
        .args(["audit", "tail", "-n", "10", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VaultCreated"));
}

#[test]
fn test_audit_verify() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["audit", "verify", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

#[test]
fn test_audit_verify_after_operations() {
    let home = fresh_home();
    setup_vault(&home);

    // Do some operations to build up audit log
    sigyn(&home)
        .args([
            "secret", "set", "A", "1", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "secret", "set", "B", "2", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    // Verify chain is still valid
    sigyn(&home)
        .args(["audit", "verify", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

#[test]
fn test_audit_export_json() {
    let home = fresh_home();
    setup_vault(&home);

    let export_path = sigyn_home_path(&home).join("audit-export.json");

    sigyn(&home)
        .args([
            "audit",
            "export",
            "--output",
            export_path.to_str().unwrap(),
            "--format",
            "json",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported"));

    assert!(export_path.exists());
    let content = std::fs::read_to_string(&export_path).unwrap();
    assert!(content.contains("VaultCreated"));
}

#[test]
fn test_audit_export_csv() {
    let home = fresh_home();
    setup_vault(&home);

    let export_path = sigyn_home_path(&home).join("audit-export.csv");

    sigyn(&home)
        .args([
            "audit",
            "export",
            "--output",
            export_path.to_str().unwrap(),
            "--format",
            "csv",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&export_path).unwrap();
    assert!(content.starts_with("sequence,timestamp,action,env,actor"));
}

#[test]
fn test_audit_witness() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["audit", "witness", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Witnessed audit entry"));
}

// ─── Status & Doctor ─────────────────────────────────────────────

#[test]
fn test_status_clean() {
    let home = fresh_home();
    sigyn(&home)
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Home:"));
}

#[test]
fn test_status_with_vault() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vaults:").and(predicate::str::contains("myapp")));
}

#[test]
fn test_status_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["--json", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"home\"").and(predicate::str::contains("\"vaults\"")));
}

#[test]
fn test_doctor_clean_home() {
    let home = fresh_home();
    sigyn(&home)
        .args(["doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Doctor check complete"));
}

#[test]
fn test_doctor_with_identity_and_vault() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Doctor check complete"));
}

// ─── Import dotenv ──────────────────────────────────────────────

#[test]
fn test_import_dotenv() {
    let home = fresh_home();
    setup_vault(&home);

    // Create a .env file
    let env_file = sigyn_home_path(&home).join("test.env");
    std::fs::write(&env_file, "FOO=bar\nBAZ=qux\n").unwrap();

    sigyn(&home)
        .args([
            "import",
            "dotenv",
            env_file.to_str().unwrap(),
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported"));

    // Verify imported secrets
    sigyn(&home)
        .args([
            "secret", "get", "FOO", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("bar"));
}

#[test]
fn test_import_json() {
    let home = fresh_home();
    setup_vault(&home);

    let json_file = sigyn_home_path(&home).join("secrets.json");
    std::fs::write(&json_file, r#"{"KEY1": "val1", "KEY2": "val2"}"#).unwrap();

    sigyn(&home)
        .args([
            "import",
            "json",
            json_file.to_str().unwrap(),
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported"));
}

// ─── Run export ──────────────────────────────────────────────────

#[test]
fn test_run_export_dotenv() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret",
            "set",
            "APP_KEY",
            "my-secret",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "run", "export", "--format", "dotenv", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("APP_KEY=my-secret"));
}

#[test]
fn test_run_export_json_format() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "KEY", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "run", "export", "--format", "json", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"KEY\""));
}

#[test]
fn test_run_export_shell() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "MY_VAR", "123", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "run", "export", "--format", "shell", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("export MY_VAR="));
}

// ─── Init command ────────────────────────────────────────────────

#[test]
fn test_init() {
    let home = fresh_home();
    sigyn(&home)
        .args(["init", "--identity", "myid", "--vault", "myvault"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration initialized"));

    // Verify config was written
    let config_path = sigyn_home_path(&home).join("config.toml");
    assert!(config_path.exists());
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("myid"));
    assert!(content.contains("myvault"));
}

// ─── Error cases ─────────────────────────────────────────────────

#[test]
fn test_missing_vault_flag() {
    let home = fresh_home();
    setup_identity(&home);

    // No vault specified and no default
    sigyn(&home)
        .args(["secret", "set", "KEY", "val", "-i", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no vault specified"));
}

#[test]
fn test_secret_on_nonexistent_vault() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args([
            "secret", "set", "KEY", "val", "-v", "ghost", "-i", "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_invalid_secret_key_name() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret",
            "set",
            "invalid key!",
            "val",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .failure();
}

// ─── Multi-environment workflow ──────────────────────────────────

#[test]
fn test_multi_env_workflow() {
    let home = fresh_home();
    setup_vault(&home);

    // Set different values in dev and staging
    sigyn(&home)
        .args([
            "secret",
            "set",
            "DB_HOST",
            "localhost",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "secret",
            "set",
            "DB_HOST",
            "db.staging.internal",
            "-v",
            "myapp",
            "-e",
            "staging",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    // Verify they're independent
    sigyn(&home)
        .args([
            "secret", "get", "DB_HOST", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("localhost"));

    sigyn(&home)
        .args([
            "secret", "get", "DB_HOST", "-v", "myapp", "-e", "staging", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("db.staging.internal"));
}

// ─── Audit query ─────────────────────────────────────────────────

#[test]
fn test_audit_query() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "Q_KEY", "qval", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "audit", "query", "--env", "dev", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("matching entries"));
}

// ─── Completions ─────────────────────────────────────────────────

#[test]
fn test_completions_bash() {
    let home = fresh_home();
    sigyn(&home)
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sigyn"));
}

#[test]
fn test_completions_zsh() {
    let home = fresh_home();
    sigyn(&home).args(["completions", "zsh"]).assert().success();
}

// ─── Fork commands ──────────────────────────────────────────────

#[test]
fn test_fork_create_leashed() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "fork", "create", "my-fork", "--mode", "leashed", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created leashed fork 'my-fork'"));
}

#[test]
fn test_fork_create_unleashed() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "fork",
            "create",
            "my-fork",
            "--mode",
            "unleashed",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created unleashed fork"));
}

#[test]
fn test_fork_create_with_expiry() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "fork",
            "create",
            "temp-fork",
            "--mode",
            "leashed",
            "--expires-days",
            "7",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Created leashed fork")
                .and(predicate::str::contains("Expires in: 7 days")),
        );
}

#[test]
fn test_fork_create_invalid_mode() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "fork", "create", "bad-fork", "--mode", "invalid", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown fork mode"));
}

#[test]
fn test_fork_create_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "--json", "fork", "create", "j-fork", "--mode", "leashed", "-v", "myapp", "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"action\"").and(predicate::str::contains("fork_created")),
        );
}

#[test]
fn test_fork_list_empty() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["fork", "list", "-v", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No forks found"));
}

#[test]
fn test_fork_status() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["fork", "status", "my-fork", "-v", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: active"));
}

#[test]
fn test_fork_status_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["--json", "fork", "status", "my-fork", "-v", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\"").and(predicate::str::contains("active")));
}

#[test]
fn test_fork_sync() {
    let home = fresh_home();
    setup_vault(&home);

    // Create a fork first so sync has something to work with
    sigyn(&home)
        .args([
            "fork", "create", "my-fork", "--mode", "leashed", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args(["fork", "sync", "my-fork", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Synced fork"));
}

// ─── Sync commands ──────────────────────────────────────────────

#[test]
fn test_sync_resolve_local() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "sync",
            "resolve",
            "MY_KEY",
            "--strategy",
            "local",
            "-v",
            "myapp",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Resolved conflict"));
}

#[test]
fn test_sync_resolve_remote() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "sync",
            "resolve",
            "MY_KEY",
            "--strategy",
            "remote",
            "-v",
            "myapp",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Resolved conflict"));
}

#[test]
fn test_sync_resolve_latest() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "sync",
            "resolve",
            "MY_KEY",
            "--strategy",
            "latest",
            "-v",
            "myapp",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Resolved conflict"));
}

#[test]
fn test_sync_resolve_invalid_strategy() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "sync",
            "resolve",
            "MY_KEY",
            "--strategy",
            "bad",
            "-v",
            "myapp",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown strategy"));
}

#[test]
fn test_sync_configure() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "sync",
            "configure",
            "--remote-url",
            "https://example.com/repo.git",
            "-v",
            "myapp",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sync configuration updated"));
}

#[test]
fn test_sync_configure_auto_sync() {
    let home = fresh_home();

    sigyn(&home)
        .args(["sync", "configure", "--auto-sync", "true", "-v", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sync configuration updated"));
}

#[test]
fn test_sync_push_no_vault() {
    let home = fresh_home();

    sigyn(&home)
        .args(["sync", "push", "-v", "ghost"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_sync_pull_no_vault() {
    let home = fresh_home();

    sigyn(&home)
        .args(["sync", "pull", "-v", "ghost"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

// ─── Rotate commands ─────────────────────────────────────────────

#[test]
fn test_rotate_schedule() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["rotate", "schedule", "list", "-v", "myapp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Rotation Schedules"));
}

#[test]
fn test_rotate_key() {
    let home = fresh_home();
    setup_vault(&home);

    // Set a secret first
    sigyn(&home)
        .args([
            "secret",
            "set",
            "ROTATE_ME",
            "old-value",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "rotate",
            "key",
            "ROTATE_ME",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Rotated 'ROTATE_ME'"));
}

#[test]
fn test_rotate_key_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "RK", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "--json", "rotate", "key", "RK", "-e", "dev", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\"").and(predicate::str::contains("rotated")));
}

#[test]
fn test_rotate_key_not_found() {
    let home = fresh_home();
    setup_vault(&home);

    // Set at least one secret so env file exists
    sigyn(&home)
        .args([
            "secret", "set", "X", "x", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "rotate",
            "key",
            "NONEXISTENT",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_rotate_key_no_env() {
    let home = fresh_home();
    setup_vault(&home);

    // Create custom env but don't put secrets in it
    sigyn(&home)
        .args([
            "env",
            "create",
            "empty-env",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "rotate",
            "key",
            "ANY_KEY",
            "-e",
            "empty-env",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has no secrets"));
}

#[test]
fn test_rotate_due() {
    let home = fresh_home();
    setup_vault(&home);

    // Set a secret
    sigyn(&home)
        .args([
            "secret", "set", "OLD_KEY", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    // With max_age=0, everything should be "due"
    sigyn(&home)
        .args([
            "rotate",
            "due",
            "--max-age",
            "0",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("due for rotation"));
}

#[test]
fn test_rotate_due_nothing() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "FRESH", "new", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    // With max_age=999999, nothing should be due
    sigyn(&home)
        .args([
            "rotate",
            "due",
            "--max-age",
            "999999",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets due"));
}

#[test]
fn test_rotate_due_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "K", "v", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "--json",
            "rotate",
            "due",
            "--max-age",
            "0",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"due_count\""));
}

#[test]
fn test_rotate_dead_check() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "STALE", "data", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    // With max_age=0, everything is "dead"
    sigyn(&home)
        .args([
            "rotate",
            "dead-check",
            "--max-age",
            "0",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dead secrets found"));
}

#[test]
fn test_rotate_dead_check_clean() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "ALIVE", "ok", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "rotate",
            "dead-check",
            "--max-age",
            "999999",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No dead secrets found"));
}

#[test]
fn test_rotate_dead_check_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "K", "v", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "--json",
            "rotate",
            "dead-check",
            "--max-age",
            "0",
            "-e",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"dead_count\""));
}

#[test]
fn test_rotate_breach_mode_force() {
    let home = fresh_home();
    setup_vault(&home);

    // Add some secrets
    sigyn(&home)
        .args([
            "secret", "set", "A", "1", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();
    sigyn(&home)
        .args([
            "secret", "set", "B", "2", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "rotate",
            "breach-mode",
            "--force",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Breach mode activated"));
}

#[test]
fn test_rotate_breach_mode_force_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "S", "v", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "--json",
            "rotate",
            "breach-mode",
            "--force",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"action\"").and(predicate::str::contains("breach_mode")),
        );
}

// ─── Delegation commands ─────────────────────────────────────────

#[test]
fn test_delegation_tree() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["delegation", "tree", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Delegation Tree"));
}

#[test]
fn test_delegation_tree_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "--json",
            "delegation",
            "tree",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"vault\"")
                .and(predicate::str::contains("\"owner\""))
                .and(predicate::str::contains("\"members\"")),
        );
}

#[test]
fn test_delegation_pending_empty() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["delegation", "pending"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no pending invitations"));
}

#[test]
fn test_delegation_pending_json() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["--json", "delegation", "pending"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[]"));
}

#[test]
fn test_delegation_accept_missing_file() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["delegation", "accept", "/nonexistent/invitation.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invitation file not found"));
}

#[test]
fn test_delegation_invite_bad_fingerprint() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "delegation",
            "invite",
            "--pubkey",
            "not-hex",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid fingerprint"));
}

#[test]
fn test_delegation_invite_bad_role() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "delegation",
            "invite",
            "--pubkey",
            "aabbccddaabbccddaabbccddaabbccdd",
            "--role",
            "superadmin",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown role"));
}

#[test]
fn test_delegation_revoke_bad_fingerprint() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "delegation",
            "revoke",
            "not-a-fingerprint",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid fingerprint"));
}

#[test]
fn test_delegation_member_alias() {
    let home = fresh_home();
    setup_identity(&home);

    // "member" is an alias for "delegation"
    sigyn(&home)
        .args(["member", "pending"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no pending invitations"));
}

// ─── MFA commands ───────────────────────────────────────────────

#[test]
fn test_mfa_status_not_enrolled() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["mfa", "status", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MFA Status").and(predicate::str::contains("Enrolled:")));
}

#[test]
fn test_mfa_status_json() {
    let home = fresh_home();
    setup_identity(&home);

    sigyn(&home)
        .args(["--json", "mfa", "status", "-i", "testuser"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"enrolled\"")
                .and(predicate::str::contains("\"session_active\"")),
        );
}

// ─── Project commands ───────────────────────────────────────────

#[test]
fn test_project_init_global() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "project",
            "init",
            "--global",
            "--vault",
            "myapp",
            "--identity",
            "testuser",
            "--env",
            "dev",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));

    // Verify the file was created
    let project_path = home.path().join("project.toml");
    assert!(project_path.exists());
    let content = std::fs::read_to_string(&project_path).unwrap();
    assert!(content.contains("vault = \"myapp\""));
    assert!(content.contains("identity = \"testuser\""));
    assert!(content.contains("env = \"dev\""));
}

#[test]
fn test_project_init_global_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "--json",
            "project",
            "init",
            "--global",
            "--vault",
            "myapp",
            "--identity",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"path\"").and(predicate::str::contains("\"project\"")));
}

#[test]
fn test_project_init_duplicate() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "project",
            "init",
            "--global",
            "--vault",
            "myapp",
            "--identity",
            "testuser",
        ])
        .assert()
        .success();

    // Second time should fail
    sigyn(&home)
        .args([
            "project",
            "init",
            "--global",
            "--vault",
            "myapp",
            "--identity",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

// ─── Policy member management ───────────────────────────────────

#[test]
fn test_policy_member_add() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "member-add",
            "aabbccddaabbccddaabbccddaabbccdd",
            "--role",
            "readonly",
            "--envs",
            "dev,staging",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added member"));
}

#[test]
fn test_policy_member_add_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "--json",
            "policy",
            "member-add",
            "aabbccddaabbccddaabbccddaabbccdd",
            "--role",
            "contributor",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"action\"").and(predicate::str::contains("member_added")),
        );
}

#[test]
fn test_policy_member_add_duplicate() {
    let home = fresh_home();
    setup_vault(&home);

    let fp = "aabbccddaabbccddaabbccddaabbccdd";

    sigyn(&home)
        .args(["policy", "member-add", fp, "-v", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args(["policy", "member-add", fp, "-v", "myapp", "-i", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already in the policy"));
}

#[test]
fn test_policy_member_add_bad_role() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "member-add",
            "aabbccddaabbccddaabbccddaabbccdd",
            "--role",
            "superuser",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown role"));
}

#[test]
fn test_policy_member_add_bad_fingerprint() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "member-add",
            "tooshort",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid fingerprint"));
}

#[test]
fn test_policy_member_remove() {
    let home = fresh_home();
    setup_vault(&home);

    let fp = "aabbccddaabbccddaabbccddaabbccdd";

    // Add first
    sigyn(&home)
        .args(["policy", "member-add", fp, "-v", "myapp", "-i", "testuser"])
        .assert()
        .success();

    // Remove
    sigyn(&home)
        .args([
            "policy",
            "member-remove",
            fp,
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed member"));
}

#[test]
fn test_policy_member_remove_not_found() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "member-remove",
            "aabbccddaabbccddaabbccddaabbccdd",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found in policy"));
}

#[test]
fn test_policy_show_with_members() {
    let home = fresh_home();
    setup_vault(&home);

    // Add a member
    sigyn(&home)
        .args([
            "policy",
            "member-add",
            "aabbccddaabbccddaabbccddaabbccdd",
            "--role",
            "contributor",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    // Show should now list the member
    sigyn(&home)
        .args(["policy", "show", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Vault Policy")
                .and(predicate::str::contains("aabbccddaabbccdd"))
                .and(predicate::str::contains("contributor")),
        );
}

#[test]
fn test_policy_show_with_members_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "member-add",
            "aabbccddaabbccddaabbccddaabbccdd",
            "--role",
            "auditor",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args(["--json", "policy", "show", "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"members\"")
                .and(predicate::str::contains("\"fingerprint\"")),
        );
}

#[test]
fn test_policy_check_owner_allow() {
    let home = fresh_home();
    setup_vault(&home);

    // Get the owner fingerprint from the text output of identity show
    let output = sigyn(&home)
        .args(["identity", "show", "testuser"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let fp = stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .unwrap()
        .split("Fingerprint:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    sigyn(&home)
        .args([
            "policy", "check", &fp, "read", "--env", "dev", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOW"));
}

#[test]
fn test_policy_check_unknown_deny() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "check",
            "11223344556677881122334455667788",
            "write",
            "--env",
            "dev",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("DENY"));
}

#[test]
fn test_policy_check_bad_action() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "policy",
            "check",
            "aabbccddaabbccddaabbccddaabbccdd",
            "fly",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown action"));
}

#[test]
fn test_policy_check_json() {
    let home = fresh_home();
    setup_vault(&home);

    // Get owner fingerprint from text output
    let output = sigyn(&home)
        .args(["identity", "show", "testuser"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let fp = stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .unwrap()
        .split("Fingerprint:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    sigyn(&home)
        .args([
            "--json", "policy", "check", &fp, "read", "-v", "myapp", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"decision\""));
}

// ─── Run export formats ─────────────────────────────────────────

#[test]
fn test_run_export_docker() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "KEY", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "run", "export", "--format", "docker", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY"));
}

#[test]
fn test_run_export_k8s() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "KEY", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "run",
            "export",
            "--format",
            "k8s",
            "--name",
            "my-k8s-secret",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"kind\": \"Secret\"")
                .and(predicate::str::contains("my-k8s-secret")),
        );
}

#[test]
fn test_run_export_invalid_format() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "KEY", "val", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "run", "export", "--format", "yaml", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown format"));
}

#[test]
fn test_run_export_no_secrets() {
    let home = fresh_home();
    setup_vault(&home);

    // Create a new env but don't add secrets, then remove env file
    sigyn(&home)
        .args([
            "env",
            "create",
            "empty-env",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();
    let env_file = home
        .path()
        .join("vaults")
        .join("myapp")
        .join("envs")
        .join("empty-env.vault");
    if env_file.exists() {
        std::fs::remove_file(&env_file).unwrap();
    }

    sigyn(&home)
        .args([
            "run",
            "export",
            "--format",
            "dotenv",
            "-v",
            "myapp",
            "-e",
            "empty-env",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has no secrets"));
}

#[test]
fn test_run_exec_no_command() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "secret", "set", "X", "y", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args(["run", "exec", "-v", "myapp", "-e", "dev", "-i", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no command specified"));
}

// ─── Import edge cases ──────────────────────────────────────────

#[test]
fn test_import_dotenv_with_comments() {
    let home = fresh_home();
    setup_vault(&home);

    let env_file = sigyn_home_path(&home).join("commented.env");
    std::fs::write(
        &env_file,
        "# This is a comment\nVALID_KEY=value\n  # another comment\nSECOND=two\n",
    )
    .unwrap();

    sigyn(&home)
        .args([
            "import",
            "dotenv",
            env_file.to_str().unwrap(),
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported"));

    sigyn(&home)
        .args([
            "secret",
            "get",
            "VALID_KEY",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("value"));
}

#[test]
fn test_import_dotenv_missing_file() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args([
            "import",
            "dotenv",
            "/tmp/does-not-exist.env",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read"));
}

#[test]
fn test_import_json_nested() {
    let home = fresh_home();
    setup_vault(&home);

    // Nested JSON values should be flattened or handled
    let json_file = sigyn_home_path(&home).join("nested.json");
    std::fs::write(&json_file, r#"{"SIMPLE": "yes", "NUM": "42"}"#).unwrap();

    sigyn(&home)
        .args([
            "import",
            "json",
            json_file.to_str().unwrap(),
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported"));
}

#[test]
fn test_import_json_invalid() {
    let home = fresh_home();
    setup_vault(&home);

    let json_file = sigyn_home_path(&home).join("bad.json");
    std::fs::write(&json_file, "not json at all").unwrap();

    sigyn(&home)
        .args([
            "import",
            "json",
            json_file.to_str().unwrap(),
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .failure();
}

#[test]
fn test_import_dotenv_json_output() {
    let home = fresh_home();
    setup_vault(&home);

    let env_file = sigyn_home_path(&home).join("j.env");
    std::fs::write(&env_file, "A=1\n").unwrap();

    sigyn(&home)
        .args([
            "--json",
            "import",
            "dotenv",
            env_file.to_str().unwrap(),
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"imported\"").and(predicate::str::contains("\"provider\"")),
        );
}

// ─── Delegation invite + accept workflow ─────────────────────────

#[test]
fn test_delegation_invite_and_accept() {
    let home = fresh_home();
    setup_vault(&home);

    // Create a second identity (the invitee)
    sigyn(&home)
        .args(["identity", "create", "-n", "bob", "-E", "bob@example.com"])
        .assert()
        .success();

    // Get bob's fingerprint from text output
    let output = sigyn(&home)
        .args(["identity", "show", "bob"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let bob_fp = stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .unwrap()
        .split("Fingerprint:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    // Invite bob
    let invite_output = sigyn(&home)
        .args([
            "delegation",
            "invite",
            "--pubkey",
            &bob_fp,
            "--role",
            "readonly",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .output()
        .unwrap();
    assert!(invite_output.status.success());
    let invite_stdout = String::from_utf8_lossy(&invite_output.stdout);
    assert!(invite_stdout.contains("Invited"));

    // Extract invitation file path from output
    let inv_line = invite_stdout
        .lines()
        .find(|l| l.contains("Invitation file:"))
        .unwrap();
    let inv_path = inv_line.split("Invitation file: ").nth(1).unwrap().trim();

    // Pending should show it
    sigyn(&home)
        .args(["delegation", "pending"])
        .assert()
        .success()
        .stdout(predicate::str::contains("myapp"));

    // Accept the invitation
    sigyn(&home)
        .args(["delegation", "accept", inv_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Invitation accepted"));
}

#[test]
fn test_delegation_invite_json() {
    let home = fresh_home();
    setup_vault(&home);

    sigyn(&home)
        .args(["identity", "create", "-n", "charlie"])
        .assert()
        .success();

    let output = sigyn(&home)
        .args(["identity", "show", "charlie"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let charlie_fp = stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .unwrap()
        .split("Fingerprint:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    sigyn(&home)
        .args([
            "--json",
            "delegation",
            "invite",
            "--pubkey",
            &charlie_fp,
            "--role",
            "contributor",
            "--envs",
            "dev,staging",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"invitation_created\"")
                .and(predicate::str::contains("\"invitation_id\"")),
        );
}

// ─── Delegation revoke workflow ──────────────────────────────────

#[test]
fn test_delegation_revoke_member() {
    let home = fresh_home();
    setup_vault(&home);

    // Add a member via policy first (simpler than invite flow for this test)
    let fp = "aabbccddaabbccddaabbccddaabbccdd";
    sigyn(&home)
        .args([
            "policy",
            "member-add",
            fp,
            "--role",
            "readonly",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    // Revoke via delegation revoke
    sigyn(&home)
        .args(["delegation", "revoke", fp, "-v", "myapp", "-i", "testuser"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Revoked access"));
}

#[test]
fn test_delegation_revoke_cascade() {
    let home = fresh_home();
    setup_vault(&home);

    let fp = "aabbccddaabbccddaabbccddaabbccdd";
    sigyn(&home)
        .args(["policy", "member-add", fp, "-v", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "delegation",
            "revoke",
            fp,
            "--cascade",
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Revoked access").and(predicate::str::contains("cascade")),
        );
}

#[test]
fn test_delegation_revoke_json() {
    let home = fresh_home();
    setup_vault(&home);

    let fp = "aabbccddaabbccddaabbccddaabbccdd";
    sigyn(&home)
        .args(["policy", "member-add", fp, "-v", "myapp", "-i", "testuser"])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "--json",
            "delegation",
            "revoke",
            fp,
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"action\"").and(predicate::str::contains("\"revoked\"")),
        );
}
