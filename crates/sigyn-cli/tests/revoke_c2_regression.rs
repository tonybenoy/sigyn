//! Regression test for finding C2: revoking two members in a single
//! `delegation revoke <fp1> <fp2>` invocation used to reseal the manifest,
//! env files, and audit log under a rotated vault key that was never written
//! to the on-disk members header — permanently bricking the vault for every
//! member, including the owner. This exercises the full CLI path and asserts
//! the owner can still unlock and read secrets after a two-member batch revoke.

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

/// Create an identity and return its fingerprint.
fn create_identity(home: &TempDir, name: &str) -> String {
    sigyn(home)
        .args(["identity", "create", "-n", name])
        .assert()
        .success();
    let output = sigyn(home)
        .args(["identity", "show", name])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .unwrap()
        .split("Fingerprint:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string()
}

fn invite(home: &TempDir, fp: &str) {
    sigyn(home)
        .args([
            "delegation",
            "invite",
            "--pubkey",
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
}

#[test]
fn revoking_two_members_at_once_does_not_brick_the_vault() {
    let home = fresh_home();

    // Owner + vault + a secret.
    sigyn(&home)
        .args(["identity", "create", "-n", "testuser"])
        .assert()
        .success();
    sigyn(&home)
        .args(["vault", "create", "myapp", "-i", "testuser"])
        .assert()
        .success();
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
        .success();

    // Two real members (invite grants an envelope key slot immediately, so
    // revoking them rotates the vault key and reseals the data files).
    let bob_fp = create_identity(&home, "bob");
    let carol_fp = create_identity(&home, "carol");
    invite(&home, &bob_fp);
    invite(&home, &carol_fp);

    // The bug: both fingerprints in ONE invocation.
    sigyn(&home)
        .args([
            "delegation",
            "revoke",
            &bob_fp,
            &carol_fp,
            "-v",
            "myapp",
            "-i",
            "testuser",
        ])
        .assert()
        .success();

    // The vault must still unlock for the owner and the secret must be intact.
    sigyn(&home)
        .args([
            "secret", "get", "DB_URL", "-v", "myapp", "-e", "dev", "-i", "testuser",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://localhost"));

    // Both revoked members must be gone from the policy.
    let tree = sigyn(&home)
        .args(["delegation", "tree", "-v", "myapp", "-i", "testuser"])
        .output()
        .unwrap();
    let tree_out = String::from_utf8_lossy(&tree.stdout);
    assert!(
        !tree_out.contains(&bob_fp[..12]),
        "bob should have been revoked, tree still lists him"
    );
    assert!(
        !tree_out.contains(&carol_fp[..12]),
        "carol should have been revoked, tree still lists her"
    );
}
