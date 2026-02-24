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
