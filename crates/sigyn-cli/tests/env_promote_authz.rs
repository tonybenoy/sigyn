//! End-to-end authorization tests for `env promote`.
//!
//! Regression coverage for the finding that `env promote` only evaluated
//! access against the SOURCE environment, letting a member with no write
//! access to the TARGET environment push secrets into it. Promotion now
//! requires Read on the source env AND Write on the target env.

#[allow(deprecated)]
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASSPHRASE: &str = "test-pass-123";

fn fresh_home() -> TempDir {
    tempfile::tempdir().unwrap()
}

#[allow(deprecated)]
fn sigyn(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("sigyn").unwrap();
    cmd.env("SIGYN_HOME", home.path())
        .env("SIGYN_PASSPHRASE", PASSPHRASE)
        .env("NO_COLOR", "1");
    cmd
}

/// Create an identity and return its hex fingerprint (parsed from the
/// `Fingerprint: <hex>` line printed on creation).
fn create_identity(home: &TempDir, name: &str) -> String {
    let assert = sigyn(home)
        .args(["identity", "create", "-n", name])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let line = stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .unwrap_or_else(|| panic!("no fingerprint line for identity '{}':\n{}", name, stdout));
    line.split("Fingerprint:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string()
}

/// Set up an owner (alice), a vault (default envs dev/staging/prod), a secret
/// in dev, and a member (bob). Returns bob's fingerprint.
fn setup(home: &TempDir) -> String {
    create_identity(home, "alice");
    let bob_fp = create_identity(home, "bob");

    sigyn(home)
        .args(["vault", "create", "myapp", "-i", "alice"])
        .assert()
        .success();

    sigyn(home)
        .args([
            "secret",
            "set",
            "API_KEY",
            "dev-secret",
            "-v",
            "myapp",
            "-e",
            "dev",
            "-i",
            "alice",
        ])
        .assert()
        .success();

    bob_fp
}

#[test]
fn test_promote_denied_without_write_on_target_env() {
    let home = fresh_home();
    let bob_fp = setup(&home);

    // Invite bob as MANAGER but scoped to the dev env ONLY. Manager clears the
    // Promote role gate and can Read the dev source, so the only control that
    // must stop bob from promoting into prod is the target-env Write check.
    sigyn(&home)
        .args([
            "delegation",
            "invite",
            "--pubkey",
            &bob_fp,
            "--role",
            "manager",
            "--envs",
            "dev",
            "-v",
            "myapp",
            "-i",
            "alice",
        ])
        .assert()
        .success();

    // bob promotes dev -> prod: denied by the target-env authorization.
    sigyn(&home)
        .args([
            "env", "promote", "--from", "dev", "--to", "prod", "-v", "myapp", "-i", "bob",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("access denied").and(predicate::str::contains("prod")));

    // The denial must be effective: prod must not have received the secret.
    // bob has no prod access, so verify as the owner.
    sigyn(&home)
        .args([
            "secret", "get", "API_KEY", "-v", "myapp", "-e", "prod", "-i", "alice",
        ])
        .assert()
        .failure();
}

#[test]
fn test_promote_allowed_with_read_source_and_write_target() {
    let home = fresh_home();
    let bob_fp = setup(&home);

    // Invite bob as MANAGER scoped to BOTH dev and prod: he can Read the source
    // and Write the target, so promotion must succeed.
    sigyn(&home)
        .args([
            "delegation",
            "invite",
            "--pubkey",
            &bob_fp,
            "--role",
            "manager",
            "--envs",
            "dev,prod",
            "-v",
            "myapp",
            "-i",
            "alice",
        ])
        .assert()
        .success();

    sigyn(&home)
        .args([
            "env", "promote", "--from", "dev", "--to", "prod", "-v", "myapp", "-i", "bob",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Promoted"));

    // The promoted secret is now readable in prod.
    sigyn(&home)
        .args([
            "secret", "get", "API_KEY", "-v", "myapp", "-e", "prod", "-i", "bob",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev-secret"));
}

#[test]
fn test_owner_promote_still_works() {
    // Guard: the added source/target checks must not break the owner path,
    // since the owner bypasses policy evaluation.
    let home = fresh_home();
    setup(&home);

    sigyn(&home)
        .args([
            "env", "promote", "--from", "dev", "--to", "prod", "-v", "myapp", "-i", "alice",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Promoted"));
}
