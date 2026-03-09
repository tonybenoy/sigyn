# Testing

Sigyn uses a multi-layered testing strategy: unit tests, integration tests, CLI workflow tests, end-to-end tests, and adversarial security tests.

## Quick Reference

```bash
# Unit + integration tests (fast, recommended during development)
cargo test --all --features sigyn-cli/fast-kdf

# Single crate
cargo test -p sigyn-core
cargo test -p sigyn-engine
cargo test -p sigyn-integration-tests

# Lint
cargo clippy -- -D warnings

# Format check
cargo fmt --all -- --check

# E2E test (requires release build + GitHub repos)
cargo build --release
bash tests/e2e_test.sh

# Adversarial security test (requires release build)
cargo build --release
bash tests/adversarial_test.sh
```

---

## Test Layers

### 1. Unit Tests

Colocated with source code (`#[cfg(test)]` modules). Run with `cargo test`.

**Focus areas:**
- Cryptographic roundtrips (encrypt→decrypt, sign→verify)
- Policy evaluation edge cases (role hierarchy, delegation depth)
- CRDT merge logic and conflict resolution
- Validation functions (key names, vault names, env names)
- Serialization/deserialization (CBOR, TOML, JSON)

**Key flag:** Use `--features sigyn-cli/fast-kdf` to use lightweight Argon2 parameters during tests. Without this flag, identity creation takes ~650ms per test (production KDF strength).

```bash
# All unit tests with fast KDF
cargo test --all --features sigyn-cli/fast-kdf

# Run a specific test
cargo test --all --features sigyn-cli/fast-kdf test_valid_delegation
```

### 2. Integration Tests

Located in `tests/integration/src/`. These test cross-crate interactions using `sigyn-engine` directly (no CLI).

| Module | Coverage |
|--------|----------|
| `vault_lifecycle.rs` | Create, open, delete vaults |
| `member_access.rs` | Member key slots, access control |
| `delegation_invite.rs` | Invitation create, accept, verify |
| `revocation.rs` | Revoke, cascade revoke, key rotation |
| `policy_constraints.rs` | Role checks, delegation depth, delegatee limits |
| `audit_chain.rs` | Hash chain integrity, signature verification |
| `secret_types.rs` | Secret value types and validation |
| `env_promotion.rs` | Environment copy, promote, diff |
| `forks_leash.rs` | Fork creation and management |

```bash
cargo test -p sigyn-integration-tests
```

### 3. CLI Workflow Tests

Located in `crates/sigyn-cli/tests/cli_workflows.rs`. Uses `assert_cmd` to test the compiled binary.

Tests actual CLI commands in an isolated `SIGYN_HOME`:
- Identity CRUD
- Vault creation and listing
- Secret set/get/list/remove
- Delegation invite/accept/revoke
- Error messages and edge cases

```bash
cargo test -p sigyn-cli --test cli_workflows
```

### 4. End-to-End Test (`tests/e2e_test.sh`)

A comprehensive bash script that tests all Sigyn features with 7 team personas across 3 vaults. Runs ~170 tests across 19 phases.

**Prerequisites:**
- Release build: `cargo build --release`
- `gh` CLI authenticated (for GitHub repo operations)
- Git SSH access configured
- `python3` available

**What it tests:**

| Phase | Tests | Coverage |
|-------|-------|----------|
| Identity | 9 | Create 7 personas, list, show |
| Vaults | 9 | 3 vaults, custom envs, TOFU |
| Delegation | 12 | Direct, chained, bulk invite |
| Secrets | 34 | CRUD, RBAC, generate, search, import |
| Env Ops | 7 | Diff, clone, promote, copy |
| Sync | 9 | Configure, push, pull, status |
| Run & Export | 10 | 5 export formats, injection |
| Audit | 6 | Tail, verify, export |
| Rotation | 6 | Manual, schedule, due |
| Advanced Delegation | 10 | Cascade, env revoke, policy |
| Security | 22 | Tamper, traversal, RBAC boundaries |

**Running:**

```bash
# Full run (creates isolated SIGYN_HOME in /tmp)
bash tests/e2e_test.sh

# The script is idempotent — safe to re-run
```

**Output:** Color-coded results with pass/fail/skip counts and a summary at the end.

**Test helpers in the script:**

| Helper | Usage |
|--------|-------|
| `assert_ok "desc" cmd...` | Assert command succeeds (exit 0, no error text) |
| `assert_fail "desc" cmd...` | Assert command fails (non-zero exit or error text) |
| `assert_contains "desc" "needle" cmd...` | Assert stdout contains text |
| `assert_not_contains "desc" "needle" cmd...` | Assert stdout does NOT contain text |

### 5. Adversarial Security Test (`tests/adversarial_test.sh`)

Simulates a malicious actor attempting to break vault security. Tests 32+ attack vectors across 10 categories.

**Prerequisites:**
- Release build: `cargo build --release`
- `python3` (for bit-flip tampering)

**Attack categories:**

| Category | Attacks | Description |
|----------|---------|-------------|
| Unauthorized access | 4 | Rogue identity, wrong passphrase, env boundaries |
| File tampering | 7 | Bit-flip on all file types, zero-fill, truncate, trailing junk |
| Privilege escalation | 5 | Contributor invite/revoke/cross-env, non-member write/list |
| Stolen files | 2 | Copied vault, copied identity + wrong passphrase |
| Replay attacks | 3 | Replay used invitation, tamper invitation, forge invitation |
| Audit attacks | 2 | Delete audit log, corrupt entries |
| Path traversal | 3 | Symlink, vault name traversal, env name traversal |
| Crypto exposure | 3 | Plaintext in files, plaintext keys, passphrase leak to child |
| Cross-vault | 3 | Swap headers, policies, env files between vaults |
| Post-revocation | 2 | Read/write after revocation |

**Running:**

```bash
# Run with default binary location
bash tests/adversarial_test.sh

# Run with custom binary
bash tests/adversarial_test.sh ./target/debug/sigyn
```

**Exit code:** 0 if all attacks defended, non-zero = number of breaches found.

---

## Writing Tests

### Unit test conventions

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test fingerprints
    fn test_fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    #[test]
    fn test_my_feature() {
        // Arrange → Act → Assert
    }
}
```

### CLI workflow test pattern

```rust
#[test]
fn test_something() {
    let home = fresh_home();       // Creates isolated SIGYN_HOME in /tmp
    setup_identity(&home);         // Creates "alice" identity
    setup_vault(&home);            // Creates "test-vault" with dev env

    sigyn(&home)
        .args(["secret", "set", "KEY", "VALUE", "-v", "test-vault", "-e", "dev"])
        .assert()
        .success();

    sigyn(&home)
        .args(["secret", "get", "KEY", "-v", "test-vault", "-e", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALUE"));
}
```

### E2E test pattern

```bash
# In tests/e2e_test.sh — add to the appropriate phase section:

assert_ok "My new feature works" \
    "$SIGYN" my-command --flag value -v vault-name -i alice

assert_fail "My new feature rejects bad input" \
    "$SIGYN" my-command --flag invalid -v vault-name -i alice

assert_contains "Output includes expected text" "expected-text" \
    "$SIGYN" my-command -v vault-name -i alice
```

---

## CI Integration

Tests run automatically in CI. The recommended CI configuration:

```yaml
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all --features sigyn-cli/fast-kdf
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --all -- --check
```

For E2E and adversarial tests in CI, build the release binary first:

```yaml
  e2e:
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: bash tests/adversarial_test.sh
```

---

## Test Files

```
tests/
├── e2e_test.sh              # End-to-end bash test (170 tests, 19 phases)
├── adversarial_test.sh       # Adversarial security test (32+ attacks)
├── E2E_TEST_PLAN.md          # Detailed test plan specification
├── E2E_TEST_RESULTS.md       # Latest test results and bug tracking
└── integration/
    └── src/
        ├── lib.rs            # Module registry
        ├── audit_chain.rs
        ├── delegation_invite.rs
        ├── env_promotion.rs
        ├── forks_leash.rs
        ├── member_access.rs
        ├── policy_constraints.rs
        ├── revocation.rs
        ├── secret_types.rs
        └── vault_lifecycle.rs

crates/sigyn-cli/tests/
    └── cli_workflows.rs      # CLI command workflow tests (assert_cmd)
```
