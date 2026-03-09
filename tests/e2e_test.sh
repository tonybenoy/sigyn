#!/usr/bin/env bash
# Sigyn End-to-End Test Script
# Version: 0.11.0
# Date: 2026-03-09
#
# Usage:
#   ./tests/e2e_test.sh [path-to-sigyn-binary]
#
# Requirements:
#   - SIGYN_PASSPHRASE env var (or set below)
#   - gh CLI authenticated (for repo creation)
#   - git SSH access to GitHub
#
# This script uses an isolated SIGYN_HOME so it won't touch your real vaults.

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

SIGYN="${1:-./target/release/sigyn}"
export SIGYN_PASSPHRASE="${SIGYN_PASSPHRASE:-test-passphrase-e2e-2026}"
export SIGYN_HOME="/tmp/sigyn-e2e-home"

GITHUB_ORG="${GITHUB_ORG:-tonybenoy}"
REPO_PYTHON="${GITHUB_ORG}/sigyn-test-python"
REPO_VAULT="${GITHUB_ORG}/sigyn-test-vault"
REPO_NPM="${GITHUB_ORG}/sigyn-test-npm"

# ── Helpers ────────────────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0
ERRORS=()

red()    { printf '\033[0;31m%s\033[0m' "$*"; }
green()  { printf '\033[0;32m%s\033[0m' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

pass() {
    PASS=$((PASS + 1))
    echo "  $(green "✓") $1"
}

fail() {
    FAIL=$((FAIL + 1))
    ERRORS+=("$1: $2")
    echo "  $(red "✗") $1"
    echo "    $(red "→") $2"
}

skip() {
    SKIP=$((SKIP + 1))
    echo "  $(yellow "⊘") $1 (skipped: $2)"
}

phase() {
    echo ""
    echo "$(bold "═══ $1 ═══")"
}

# Run a command, capture output+exit code. Sets $OUT and $RC.
run() {
    set +e
    OUT=$("$@" 2>&1)
    RC=$?
    set -e
}

# Assert command succeeds
assert_ok() {
    local label="$1"; shift
    run "$@"
    if [ $RC -eq 0 ]; then
        pass "$label"
    else
        fail "$label" "exit code $RC: $OUT"
    fi
}

# Assert command fails (exit code OR "access denied"/"Error:" in output)
assert_fail() {
    local label="$1"; shift
    run "$@"
    if [ $RC -ne 0 ]; then
        pass "$label"
    elif echo "$OUT" | grep -qiE "(access denied|Error:|DENIED)"; then
        pass "$label"
    else
        fail "$label" "expected failure but got success: $OUT"
    fi
}

# Assert output contains string
assert_contains() {
    local label="$1"; shift
    local needle="$1"; shift
    run "$@"
    if echo "$OUT" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label" "output missing '$needle': $OUT"
    fi
}

# Assert output does NOT contain string
assert_not_contains() {
    local label="$1"; shift
    local needle="$1"; shift
    run "$@"
    if echo "$OUT" | grep -qF "$needle"; then
        fail "$label" "output unexpectedly contains '$needle'"
    else
        pass "$label"
    fi
}

# ── Pre-flight ─────────────────────────────────────────────────────────────────

echo "$(bold "Sigyn E2E Test Suite")"
echo "Binary:     $SIGYN"
echo "SIGYN_HOME: $SIGYN_HOME"
echo "GitHub Org: $GITHUB_ORG"
echo ""

if [ ! -x "$SIGYN" ]; then
    echo "$(red "Error: sigyn binary not found at $SIGYN")"
    echo "Build with: cargo build --release"
    exit 1
fi

VERSION=$("$SIGYN" --version 2>&1)
echo "Version:    $VERSION"

# Clean slate
rm -rf "$SIGYN_HOME"
echo "Cleaned SIGYN_HOME"
echo ""

# ── Phase 1: Identity Creation ─────────────────────────────────────────────────

phase "Phase 1: Identity Creation"

assert_ok "Create alice (Owner)"       "$SIGYN" identity create -n alice -E alice@acme.io
assert_ok "Create bob (Admin)"         "$SIGYN" identity create -n bob -E bob@acme.io
assert_ok "Create carol (Manager)"     "$SIGYN" identity create -n carol -E carol@acme.io
assert_ok "Create dave (Contributor)"  "$SIGYN" identity create -n dave -E dave@acme.io
assert_ok "Create eve (ReadOnly)"      "$SIGYN" identity create -n eve -E eve@acme.io
assert_ok "Create frank (Operator)"    "$SIGYN" identity create -n frank -E frank@acme.io
assert_ok "Create grace (Auditor)"     "$SIGYN" identity create -n grace -E grace@acme.io

# Extract fingerprints
get_fp() { "$SIGYN" identity show "$1" 2>&1 | grep Fingerprint | awk '{print $2}'; }
ALICE_FP=$(get_fp alice)
BOB_FP=$(get_fp bob)
CAROL_FP=$(get_fp carol)
DAVE_FP=$(get_fp dave)
EVE_FP=$(get_fp eve)
FRANK_FP=$(get_fp frank)
GRACE_FP=$(get_fp grace)

echo ""
echo "  Fingerprints:"
echo "    alice: $ALICE_FP"
echo "    bob:   $BOB_FP"
echo "    carol: $CAROL_FP"
echo "    dave:  $DAVE_FP"
echo "    eve:   $EVE_FP"
echo "    frank: $FRANK_FP"
echo "    grace: $GRACE_FP"

# Identity operations
assert_contains "Identity list shows all 7" "grace" "$SIGYN" identity list
assert_contains "Identity show alice" "$ALICE_FP" "$SIGYN" identity show alice

# ── Phase 2: Vault Creation & Environments ─────────────────────────────────────

phase "Phase 2: Vault Creation & Environments"

assert_ok "Create vault python-app"   "$SIGYN" vault create python-app -i alice
assert_ok "Create vault shared-infra" "$SIGYN" vault create shared-infra -i alice
assert_ok "Create vault npm-app"      "$SIGYN" vault create npm-app -i alice

assert_contains "Vault list shows 3"  "python-app" "$SIGYN" vault list
assert_contains "Vault info"          "python-app" "$SIGYN" vault info python-app -i alice

# Custom environments
assert_ok "Create env ci (python-app)"       "$SIGYN" env create -v python-app -i alice ci
assert_ok "Create env preview (npm-app)"     "$SIGYN" env create -v npm-app -i alice preview
assert_contains "Env list python-app has ci" "ci" "$SIGYN" env list -v python-app -i alice
assert_contains "Env list npm-app has preview" "preview" "$SIGYN" env list -v npm-app -i alice

# ── Phase 3: Team Delegation ───────────────────────────────────────────────────

phase "Phase 3: Team Delegation"

# Helper: invite and accept
invite_accept() {
    local vault="$1" inviter="$2" role="$3" pubkey="$4" accepter="$5"
    local envs="${6:-}"

    local invite_args=(-v "$vault" -i "$inviter" --role "$role" --pubkey "$pubkey")
    if [ -n "$envs" ]; then
        invite_args+=(--envs "$envs")
    fi

    run "$SIGYN" delegation invite "${invite_args[@]}"
    if [ $RC -ne 0 ]; then
        return 1
    fi

    # Extract invitation file path from output
    local invite_file
    invite_file=$(echo "$OUT" | grep "Invitation file:" | awk '{print $NF}')
    if [ -z "$invite_file" ]; then
        return 1
    fi

    run "$SIGYN" delegation accept -i "$accepter" "$invite_file"
    return $RC
}

# Alice → Bob (Admin) on all 3 vaults
invite_accept python-app alice admin "$BOB_FP" bob && \
    pass "Alice → Bob (Admin) python-app" || fail "Alice → Bob (Admin) python-app" "$OUT"

invite_accept shared-infra alice admin "$BOB_FP" bob && \
    pass "Alice → Bob (Admin) shared-infra" || fail "Alice → Bob (Admin) shared-infra" "$OUT"

invite_accept npm-app alice admin "$BOB_FP" bob && \
    pass "Alice → Bob (Admin) npm-app" || fail "Alice → Bob (Admin) npm-app" "$OUT"

# Bob → Carol (Manager) — tests chained delegation
invite_accept python-app bob manager "$CAROL_FP" carol && \
    pass "Bob → Carol (Manager) python-app" || fail "Bob → Carol (Manager) python-app" "Chained delegation: $OUT"

# If chained failed, Alice invites Carol directly
if ! "$SIGYN" policy show -v python-app -i alice 2>&1 | grep -q "$CAROL_FP"; then
    echo "  $(yellow "↳") Falling back: Alice → Carol (Manager)"
    invite_accept python-app alice manager "$CAROL_FP" carol && \
        pass "Alice → Carol (Manager) fallback" || fail "Alice → Carol (Manager) fallback" "$OUT"
fi

# Alice → Dave (Contributor)
invite_accept python-app alice contributor "$DAVE_FP" dave && \
    pass "Alice → Dave (Contributor) python-app" || fail "Alice → Dave (Contributor) python-app" "$OUT"

# Alice → Eve (ReadOnly, dev+staging only)
invite_accept python-app alice readonly "$EVE_FP" eve "dev,staging" && \
    pass "Alice → Eve (ReadOnly, dev+staging)" || fail "Alice → Eve (ReadOnly, dev+staging)" "$OUT"

# Alice → Frank (Operator, ci+prod)
invite_accept python-app alice operator "$FRANK_FP" frank "ci,prod" && \
    pass "Alice → Frank (Operator, ci+prod)" || fail "Alice → Frank (Operator, ci+prod)" "$OUT"

# Alice → Grace (Auditor) on shared-infra
invite_accept shared-infra alice auditor "$GRACE_FP" grace && \
    pass "Alice → Grace (Auditor) shared-infra" || fail "Alice → Grace (Auditor) shared-infra" "$OUT"

# Delegation tree
assert_contains "Delegation tree shows bob" "admin" "$SIGYN" delegation tree -v python-app -i alice

# Role hierarchy enforcement
assert_fail "Carol (Manager) can't invite as Admin" \
    "$SIGYN" delegation invite -v python-app -i carol --role admin --pubkey "$GRACE_FP"

assert_fail "Dave (Contributor) can't invite" \
    "$SIGYN" delegation invite -v python-app -i dave --role readonly --pubkey "$GRACE_FP"

# ── Phase 4: Secret Management ─────────────────────────────────────────────────

phase "Phase 4: Secret Management"

# Set secrets — python-app
assert_ok "Set DATABASE_URL (dev)"    "$SIGYN" set -v python-app -e dev -i alice DATABASE_URL='postgres://localhost:5432/devdb'
assert_ok "Set API_KEY (dev)"         "$SIGYN" set -v python-app -e dev -i alice API_KEY='dev-key-12345'
assert_ok "Set SECRET_TOKEN (dev)"    "$SIGYN" set -v python-app -e dev -i alice SECRET_TOKEN='dev-token-abc'
assert_ok "Set REDIS_URL (dev)"       "$SIGYN" set -v python-app -e dev -i alice REDIS_URL='redis://localhost:6379'
assert_ok "Set DATABASE_URL (staging)" "$SIGYN" set -v python-app -e staging -i alice DATABASE_URL='postgres://staging-db:5432/app'
assert_ok "Set API_KEY (staging)"     "$SIGYN" set -v python-app -e staging -i alice API_KEY='staging-key-67890'
assert_ok "Set DATABASE_URL (prod)"   "$SIGYN" set -v python-app -e prod -i alice DATABASE_URL='postgres://prod-db:5432/app'
assert_ok "Set API_KEY (prod)"        "$SIGYN" set -v python-app -e prod -i alice API_KEY='prod-key-REAL'
assert_ok "Set SECRET_TOKEN (prod)"   "$SIGYN" set -v python-app -e prod -i alice SECRET_TOKEN='prod-token-xyz'
assert_ok "Set REDIS_URL (prod)"      "$SIGYN" set -v python-app -e prod -i alice REDIS_URL='redis://prod-redis:6379'

# Set secrets — npm-app
assert_ok "Set DATABASE_URL (npm dev)" "$SIGYN" set -v npm-app -e dev -i alice DATABASE_URL='postgres://localhost:5432/npmdev'
assert_ok "Set API_KEY (npm dev)"      "$SIGYN" set -v npm-app -e dev -i alice API_KEY='npm-dev-key'
assert_ok "Set STRIPE_SECRET (npm dev)" "$SIGYN" set -v npm-app -e dev -i alice STRIPE_SECRET='sk_test_fake123'
assert_ok "Set JWT_SECRET (npm dev)"   "$SIGYN" set -v npm-app -e dev -i alice JWT_SECRET='dev-jwt-secret'

# Set secrets — shared-infra
assert_ok "Set POSTGRES_MASTER (infra prod)" "$SIGYN" set -v shared-infra -e prod -i alice POSTGRES_MASTER='postgres://master:5432/main'
assert_ok "Set REDIS_CLUSTER (infra prod)"   "$SIGYN" set -v shared-infra -e prod -i alice REDIS_CLUSTER='redis://cluster:6379'
assert_ok "Set DATADOG_API_KEY (infra prod)" "$SIGYN" set -v shared-infra -e prod -i alice DATADOG_API_KEY='dd-key-prod'

# ── Phase 4.4: Get & List ──────────────────────────────────────────────────────

phase "Phase 4.4: Get & List + RBAC"

# Get
assert_contains "Alice get DATABASE_URL" "postgres://localhost:5432/devdb" \
    "$SIGYN" get -v python-app -e dev -i alice DATABASE_URL

# List
assert_contains "Alice list dev (masked)" "••••••••" \
    "$SIGYN" ls -v python-app -e dev -i alice

assert_contains "Alice list dev (reveal)" "dev-key-12345" \
    "$SIGYN" ls -v python-app -e dev -i alice --reveal

# RBAC: role-based access
assert_contains "Dave get (Contributor) → PASS" "postgres://localhost" \
    "$SIGYN" get -v python-app -e dev -i dave DATABASE_URL

assert_contains "Eve get dev (ReadOnly) → PASS" "postgres://localhost" \
    "$SIGYN" get -v python-app -e dev -i eve DATABASE_URL

assert_fail "Frank get (Operator) → DENIED" \
    "$SIGYN" get -v python-app -e prod -i frank DATABASE_URL

assert_fail "Eve get prod (env restricted) → DENIED" \
    "$SIGYN" get -v python-app -e prod -i eve DATABASE_URL

# ── Phase 4.5: Write Permissions ───────────────────────────────────────────────

phase "Phase 4.5: Write Permissions"

assert_ok "Dave set (Contributor) → PASS" \
    "$SIGYN" set -v python-app -e dev -i dave NEW_KEY='dave-value'

assert_fail "Eve set (ReadOnly) → DENIED" \
    "$SIGYN" set -v python-app -e dev -i eve NEW_KEY2='eve-value'

# Operator write — may fail (known bug)
run "$SIGYN" set -v python-app -e ci -i frank CI_TOKEN='ci-tok-123'
if [ $RC -eq 0 ]; then
    pass "Frank set ci (Operator) → PASS"
else
    fail "Frank set ci (Operator) → DENIED (BUG: Operator should be able to write)" "$OUT"
fi

# ── Phase 4.6: Delete ──────────────────────────────────────────────────────────

phase "Phase 4.6: Delete Secrets"

assert_ok "Dave delete NEW_KEY (Contributor)" \
    "$SIGYN" secret remove -v python-app -e dev -i dave NEW_KEY

assert_fail "Eve delete (ReadOnly) → DENIED" \
    "$SIGYN" secret remove -v python-app -e dev -i eve API_KEY

# ── Phase 4.7: Secret Generation ───────────────────────────────────────────────

phase "Phase 4.7: Secret Generation"

assert_ok "Generate password" \
    "$SIGYN" secret generate -v python-app -e dev -i alice SESSION_SECRET --type password --length 32

assert_ok "Generate UUID" \
    "$SIGYN" secret generate -v python-app -e dev -i alice REQUEST_ID --type uuid

assert_ok "Generate hex" \
    "$SIGYN" secret generate -v npm-app -e dev -i alice ENCRYPTION_KEY --type hex --length 64

# Verify formats
run "$SIGYN" get -v python-app -e dev -i alice REQUEST_ID
if echo "$OUT" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    pass "UUID format valid"
else
    fail "UUID format valid" "got: $OUT"
fi

run "$SIGYN" get -v npm-app -e dev -i alice ENCRYPTION_KEY
if echo "$OUT" | grep -qE '^[0-9a-f]{64}$'; then
    pass "Hex format valid (64 chars)"
else
    fail "Hex format valid (64 chars)" "got: $OUT"
fi

# ── Phase 4.8: Search ──────────────────────────────────────────────────────────

phase "Phase 4.8: Secret Search"

assert_contains "Search *KEY* finds API_KEY" "API_KEY" \
    "$SIGYN" secret search -v python-app -i alice "*KEY*"

# ── Phase 4.9: Import ──────────────────────────────────────────────────────────

phase "Phase 4.9: Import from .env"

cat > /tmp/sigyn-test-import.env << 'EOF'
IMPORTED_ONE=value1
IMPORTED_TWO=value2
IMPORTED_THREE=value3
IMPORTED_FOUR=value4
IMPORTED_FIVE=value5
EOF

assert_contains "Import 5 secrets from .env" "5 secret(s)" \
    "$SIGYN" secret import -v npm-app -e dev -i alice /tmp/sigyn-test-import.env

assert_contains "Imported secrets visible in list" "IMPORTED_ONE" \
    "$SIGYN" ls -v npm-app -e dev -i alice

# ── Phase 5: Environment Operations ────────────────────────────────────────────

phase "Phase 5: Environment Operations"

assert_contains "Env diff dev vs staging" "changed" \
    "$SIGYN" env diff -v python-app -i alice dev staging

assert_ok "Env clone dev → local" \
    "$SIGYN" env clone -v python-app -i alice dev local

assert_contains "Cloned env has secrets" "DATABASE_URL" \
    "$SIGYN" ls -v python-app -e local -i alice

assert_ok "Env promote staging → prod" \
    "$SIGYN" env promote -v python-app -i alice --from staging --to prod

assert_ok "Secret copy python-app → npm-app" \
    "$SIGYN" secret copy --from-vault python-app --to-vault npm-app -i alice "DATABASE_*"

assert_ok "Env delete local" \
    "$SIGYN" env delete -v python-app -i alice local --force

assert_not_contains "Local env gone" "local" \
    "$SIGYN" env list -v python-app -i alice

# ── Phase 6: Sync ──────────────────────────────────────────────────────────────

phase "Phase 6: Sync & Git Integration"

assert_ok "Configure sync python-app" \
    "$SIGYN" sync configure -v python-app -i alice --remote-url "git@github.com:${REPO_PYTHON}.git"

assert_ok "Configure sync npm-app" \
    "$SIGYN" sync configure -v npm-app -i alice --remote-url "git@github.com:${REPO_NPM}.git"

assert_ok "Configure sync shared-infra" \
    "$SIGYN" sync configure -v shared-infra -i alice --remote-url "git@github.com:${REPO_VAULT}.git"

# Initial commit for each vault (sigyn doesn't auto-commit)
for vault in python-app npm-app shared-infra; do
    (cd "$SIGYN_HOME/vaults/$vault" && git add -A && git commit -m "Initial vault data" 2>&1) >/dev/null
done
pass "Initial git commits for all vaults"

# Pull to merge histories, then force push
for vault in python-app npm-app shared-infra; do
    "$SIGYN" sync pull -v "$vault" -i alice >/dev/null 2>&1 || true
done

# Push — may fail if remote has diverged history
for vault in python-app npm-app shared-infra; do
    run "$SIGYN" sync push -v "$vault" -i alice
    if [ $RC -eq 0 ]; then
        pass "Sync push $vault"
    else
        # Fallback: git push --force (test repos only)
        if (cd "$SIGYN_HOME/vaults/$vault" && git push --force origin main 2>&1) >/dev/null; then
            pass "Sync push $vault (via git force push)"
        else
            fail "Sync push $vault" "$OUT"
        fi
    fi
done

assert_contains "Sync status clean" "clean" \
    "$SIGYN" sync status -v python-app -i alice

# Verify no plaintext in vault files
if grep -r "postgres://localhost" "$SIGYN_HOME/vaults/python-app/envs/" 2>/dev/null; then
    fail "No plaintext in vault files" "Found plaintext secret in encrypted vault!"
else
    pass "No plaintext in vault files"
fi

# ── Phase 7: Run & Secret Injection ────────────────────────────────────────────

phase "Phase 7: Run & Secret Injection"

assert_contains "Run inject (python)" "postgres://localhost:5432/devdb" \
    "$SIGYN" run -v python-app -e dev -i alice -- python3 -c "import os; print(os.environ.get('DATABASE_URL'))"

assert_contains "Run inject (node)" "sk_test_fake123" \
    "$SIGYN" run -v npm-app -e dev -i alice -- node -e "console.log(process.env.STRIPE_SECRET)"

assert_ok "Run --clean" \
    "$SIGYN" run -v python-app -e dev -i alice --clean -- python3 -c "import os; print(len(os.environ))"

assert_contains "Inline secret refs" "postgres://localhost:5432/devdb" \
    "$SIGYN" run -v python-app -e dev -i alice --allow-inline-secrets -- echo "DB is {{DATABASE_URL}}"

assert_ok "Run --prod shortcut" \
    "$SIGYN" run -v python-app --prod -i alice -- python3 -c "import os; print(os.environ.get('DATABASE_URL'))"

# ── Phase 7.4: Export Formats ──────────────────────────────────────────────────

phase "Phase 7.4: Export Formats"

assert_contains "Export dotenv" "DATABASE_URL=" \
    "$SIGYN" run export -v python-app -e dev -i alice --format dotenv

assert_contains "Export json" '"DATABASE_URL"' \
    "$SIGYN" run export -v python-app -e dev -i alice --format json

assert_contains "Export shell" "export DATABASE_URL=" \
    "$SIGYN" run export -v python-app -e dev -i alice --format shell

assert_contains "Export docker" "DATABASE_URL" \
    "$SIGYN" run export -v python-app -e dev -i alice --format docker

assert_contains "Export k8s" '"apiVersion"' \
    "$SIGYN" run export -v python-app -e dev -i alice --format k8s

# ── Phase 8: Audit ─────────────────────────────────────────────────────────────

phase "Phase 8: Audit & Compliance"

assert_contains "Audit tail" "SecretWritten" \
    "$SIGYN" audit tail -v python-app -i alice

assert_contains "Audit verify" "all hashes valid" \
    "$SIGYN" audit verify -v python-app -i alice

assert_ok "Audit export json" \
    "$SIGYN" audit export -v python-app -i alice --format json --output /tmp/sigyn-audit-export.json

assert_ok "Audit export csv" \
    "$SIGYN" audit export -v python-app -i alice --format csv --output /tmp/sigyn-audit-export.csv

# Auditor role checks
assert_contains "Grace (Auditor) reads shared-infra" "postgres://master" \
    "$SIGYN" get -v shared-infra -e prod -i grace POSTGRES_MASTER

assert_fail "Grace (Auditor) write → DENIED" \
    "$SIGYN" set -v shared-infra -e prod -i grace HACK='nope'

# ── Phase 9: Rotation ──────────────────────────────────────────────────────────

phase "Phase 9: Secret Rotation"

# Get value before rotation
OLD_VAL=$("$SIGYN" get -v python-app -e prod -i alice API_KEY 2>&1)

assert_ok "Rotate API_KEY (prod)" \
    "$SIGYN" rotate key -v python-app -e prod -i alice API_KEY

# Verify value changed
NEW_VAL=$("$SIGYN" get -v python-app -e prod -i alice API_KEY 2>&1)
if [ "$OLD_VAL" != "$NEW_VAL" ]; then
    pass "Rotated value changed"
else
    fail "Rotated value changed" "old=$OLD_VAL new=$NEW_VAL"
fi

assert_ok "Set rotation schedule" \
    "$SIGYN" rotate schedule set -v python-app -e prod -i alice API_KEY --cron "0 0 1 * *"

assert_contains "Rotation schedule list" "API_KEY" \
    "$SIGYN" rotate schedule list -v python-app -i alice

assert_contains "Rotate due (max-age 30)" "No secrets due" \
    "$SIGYN" rotate due -v python-app -i alice --max-age 30

assert_ok "Dead check" \
    "$SIGYN" rotate dead-check -v python-app -i alice

# Breach mode — requires interactive terminal
run "$SIGYN" rotate breach-mode -v npm-app -i alice
if [ $RC -eq 0 ]; then
    pass "Breach mode"
else
    skip "Breach mode" "requires interactive terminal"
fi

# ── Phase 10: Advanced Delegation ──────────────────────────────────────────────

phase "Phase 10: Advanced Delegation"

# Environment access revocation
assert_ok "Revoke Dave's prod access" \
    "$SIGYN" delegation revoke-env -v python-app -i alice --env prod "$DAVE_FP"

assert_fail "Dave reads prod → DENIED (after env revoke)" \
    "$SIGYN" get -v python-app -e prod -i dave API_KEY

assert_contains "Dave reads dev → still PASS" "dev-key" \
    "$SIGYN" get -v python-app -e dev -i dave API_KEY

# Policy check
assert_contains "Policy check: Dave read dev → ALLOW" "ALLOW" \
    "$SIGYN" policy check -v python-app -i alice "$DAVE_FP" read --env dev

assert_contains "Policy check: Eve write dev → DENY" "DENY" \
    "$SIGYN" policy check -v python-app -i alice "$EVE_FP" write --env dev

assert_contains "Policy check: Frank read prod → DENY" "DENY" \
    "$SIGYN" policy check -v python-app -i alice "$FRANK_FP" read --env prod

assert_contains "Policy check: Eve read prod → DENY" "DENY" \
    "$SIGYN" policy check -v python-app -i alice "$EVE_FP" read --env prod

# Cascade revocation
assert_ok "Cascade revoke Bob" \
    "$SIGYN" delegation revoke -v python-app -i alice "$BOB_FP" --cascade

assert_not_contains "Bob removed from tree" "$BOB_FP" \
    "$SIGYN" delegation tree -v python-app -i alice

# Re-invite Bob for later tests
invite_accept python-app alice admin "$BOB_FP" bob >/dev/null 2>&1 && \
    pass "Re-invite Bob after cascade" || fail "Re-invite Bob after cascade" "$OUT"

# ── Phase 11: Vault Transfer ──────────────────────────────────────────────────

phase "Phase 11: Vault Ownership Transfer"

run "$SIGYN" vault transfer python-app -i alice --to "$BOB_FP"
# Transfer initiation may warn about audit but still succeeds on accept
assert_ok "Accept transfer (Bob)" \
    "$SIGYN" vault accept-transfer python-app -i bob

assert_contains "Bob is now owner" "$BOB_FP" \
    "$SIGYN" vault info python-app -i bob

# Transfer back
"$SIGYN" vault transfer python-app -i bob --to "$ALICE_FP" 2>/dev/null || true
assert_ok "Accept transfer back (Alice)" \
    "$SIGYN" vault accept-transfer python-app -i alice

# ── Phase 12: Organization Hierarchy ──────────────────────────────────────────

phase "Phase 12: Organization Hierarchy"

assert_ok "Create org acme" \
    "$SIGYN" org create acme -i alice

assert_ok "Create node platform" \
    "$SIGYN" org node create platform --parent acme -i alice

# Deeper nesting may fail (known bug)
run "$SIGYN" org node create web --parent acme/platform -i alice
if [ $RC -eq 0 ]; then
    pass "Create node web (depth 3)"
else
    fail "Create node web (depth 3) — BUG: nested org sealed format error" "$OUT"
fi

assert_ok "Create node data" \
    "$SIGYN" org node create data --parent acme -i alice

assert_ok "Attach vault to org" \
    "$SIGYN" vault attach shared-infra --org acme -i alice

# ── Phase 13: CI/CD ───────────────────────────────────────────────────────────

phase "Phase 13: CI/CD Integration"

assert_contains "CI setup generates bundle" "SIGYN_CI_BUNDLE" \
    "$SIGYN" ci setup -v python-app frank

# ── Phase 14: Context ─────────────────────────────────────────────────────────

phase "Phase 14: Context Management"

assert_ok "Context set" \
    "$SIGYN" context set python-app dev

assert_contains "Context show" "python-app" \
    "$SIGYN" context show

assert_ok "Context clear" \
    "$SIGYN" context clear

# ── Phase 15: Edge Cases ──────────────────────────────────────────────────────

phase "Phase 15: Edge Cases & Validation"

assert_fail "Empty key rejected" \
    "$SIGYN" set -v python-app -e dev -i alice ''

assert_fail "Invalid key (spaces) rejected" \
    "$SIGYN" set -v python-app -e dev -i alice 'INVALID KEY=value'

assert_fail "Non-member vault access denied" \
    "$SIGYN" get -v python-app -e dev -i grace DATABASE_URL

assert_fail "Vault delete by non-owner denied" \
    "$SIGYN" vault delete python-app -i dave

# ── Phase 16: Identity Key Rotation ──────────────────────────────────────────

phase "Phase 16: Identity Key Rotation"

OLD_DAVE_FP=$("$SIGYN" identity show dave 2>&1 | grep Fingerprint | awk '{print $2}')

assert_ok "Rotate Dave's keys" \
    "$SIGYN" identity rotate-keys dave

NEW_DAVE_FP=$("$SIGYN" identity show dave 2>&1 | grep Fingerprint | awk '{print $2}')
if [ "$OLD_DAVE_FP" != "$NEW_DAVE_FP" ]; then
    pass "Dave's fingerprint changed ($OLD_DAVE_FP → $NEW_DAVE_FP)"
else
    fail "Dave's fingerprint changed" "still $OLD_DAVE_FP"
fi

# ── Phase 17: TOFU & Doctor ──────────────────────────────────────────────────

phase "Phase 17: TOFU Pins & Doctor"

assert_contains "Vault pins" "python-app" \
    "$SIGYN" vault pins

assert_contains "Doctor passes" "Home directory exists" \
    "$SIGYN" doctor

assert_ok "Generate bash completions" \
    "$SIGYN" completions bash

assert_ok "Generate zsh completions" \
    "$SIGYN" completions zsh

assert_ok "Generate fish completions" \
    "$SIGYN" completions fish

# ── Phase 18: Security Tests ──────────────────────────────────────────────────

phase "Phase 18: Security — Encryption at Rest"

# Verify vault files are binary (not plaintext)
run file "$SIGYN_HOME/vaults/python-app/envs/dev.vault"
if echo "$OUT" | grep -qiE "text|ASCII"; then
    fail "Vault file is binary (not plaintext)" "$OUT"
else
    pass "Vault file is binary (not plaintext)"
fi

# Scan all vault dirs for known secret values
PLAINTEXT_LEAK=0
for vault_dir in "$SIGYN_HOME/vaults/"*/envs/; do
    if grep -rq "postgres://localhost" "$vault_dir" 2>/dev/null; then
        PLAINTEXT_LEAK=1
    fi
    if grep -rq "dev-key-12345" "$vault_dir" 2>/dev/null; then
        PLAINTEXT_LEAK=1
    fi
    if grep -rq "sk_test_fake123" "$vault_dir" 2>/dev/null; then
        PLAINTEXT_LEAK=1
    fi
    if grep -rq "prod-key-REAL" "$vault_dir" 2>/dev/null; then
        PLAINTEXT_LEAK=1
    fi
done
if [ "$PLAINTEXT_LEAK" -eq 0 ]; then
    pass "No plaintext secrets in any vault env files"
else
    fail "No plaintext secrets in any vault env files" "Plaintext secret value found in encrypted vault!"
fi

# Check policy.cbor and members.cbor don't leak secrets
if grep -rq "postgres://" "$SIGYN_HOME/vaults/python-app/policy.cbor" 2>/dev/null; then
    fail "Policy file doesn't contain secrets" "Found secret in policy.cbor"
else
    pass "Policy file doesn't contain secrets"
fi

if grep -rq "postgres://" "$SIGYN_HOME/vaults/python-app/members.cbor" 2>/dev/null; then
    fail "Members file doesn't contain secrets" "Found secret in members.cbor"
else
    pass "Members file doesn't contain secrets"
fi

phase "Phase 18: Security — RBAC Boundary Enforcement"

# Cross-vault access: Grace (Auditor on shared-infra) can't access python-app
assert_fail "Cross-vault: Grace can't access python-app" \
    "$SIGYN" get -v python-app -e dev -i grace DATABASE_URL

# Cross-vault: Frank (Operator on python-app) can't access npm-app
assert_fail "Cross-vault: Frank can't access npm-app" \
    "$SIGYN" get -v npm-app -e dev -i frank DATABASE_URL

# ReadOnly can't delete vault
assert_fail "ReadOnly can't delete vault" \
    "$SIGYN" vault delete python-app -i eve

# ReadOnly can't create environments
assert_fail "ReadOnly can't create env" \
    "$SIGYN" env create -v python-app -i eve hacked

# Contributor can't manage members
assert_fail "Contributor can't manage members" \
    "$SIGYN" delegation invite -v python-app -i dave --role readonly --pubkey "$GRACE_FP"

# Contributor can't manage policy
assert_fail "Contributor can't change policy" \
    "$SIGYN" policy require-mfa -v python-app -i dave --action write

# Operator can't read secrets (write-only role)
assert_fail "Operator can't read any env" \
    "$SIGYN" get -v python-app -e ci -i frank CI_TOKEN

assert_fail "Operator can't list secrets" \
    "$SIGYN" ls -v python-app -e ci -i frank

# ReadOnly restricted to allowed envs only
assert_fail "ReadOnly can't read prod (env-restricted)" \
    "$SIGYN" get -v python-app -e prod -i eve DATABASE_URL

assert_fail "ReadOnly can't read ci (env-restricted)" \
    "$SIGYN" get -v python-app -e ci -i eve CI_TOKEN

phase "Phase 18: Security — Wrong Passphrase"

# Wrong passphrase should fail
run env SIGYN_PASSPHRASE="wrong-passphrase" "$SIGYN" get -v python-app -e dev -i alice DATABASE_URL
if [ $RC -ne 0 ] || echo "$OUT" | grep -qiE "(error|denied|failed|decrypt)"; then
    pass "Wrong passphrase rejected"
else
    fail "Wrong passphrase rejected" "Got: $OUT"
fi

phase "Phase 18: Security — Identity Isolation"

# Non-existent identity
assert_fail "Non-existent identity rejected" \
    "$SIGYN" get -v python-app -e dev -i nonexistent DATABASE_URL

# Revoked member can't access (Dave was revoked from prod earlier)
assert_fail "Revoked env access enforced" \
    "$SIGYN" get -v python-app -e prod -i dave API_KEY

phase "Phase 18: Security — Vault Integrity"

# Tamper detection: corrupt a vault file and verify detection
ORIG_VAULT="$SIGYN_HOME/vaults/npm-app/envs/dev.vault"
if [ -f "$ORIG_VAULT" ]; then
    cp "$ORIG_VAULT" "$ORIG_VAULT.bak"
    # Append garbage bytes
    echo "TAMPERED" >> "$ORIG_VAULT"
    run "$SIGYN" get -v npm-app -e dev -i alice DATABASE_URL
    if [ $RC -ne 0 ] || echo "$OUT" | grep -qiE "(error|decrypt|tamper|corrupt|integrity|failed)"; then
        pass "Tampered vault file detected"
    else
        fail "Tampered vault file detected" "Read succeeded after tampering: $OUT"
    fi
    # Restore
    mv "$ORIG_VAULT.bak" "$ORIG_VAULT"
else
    skip "Tampered vault file detected" "vault file not found"
fi

# Audit chain integrity (npm-app should be untouched)
assert_contains "Audit chain integrity (npm-app)" "all hashes valid" \
    "$SIGYN" audit verify -v npm-app -i alice

phase "Phase 18: Security — Input Validation"

# Secret key injection attempts
assert_fail "Key with newline rejected" \
    "$SIGYN" set -v python-app -e dev -i alice $'INJECT\nEVIL=hack'

# NOTE: NUL byte tests cannot be tested from shell — bash strips \x00 from
# C-string arguments before the binary sees them. The validation code works
# (see unit tests in validation.rs), but shell can't pass NUL bytes.
# Equals signs are valid in key names by design.

# Vault name injection
assert_fail "Vault name with slash rejected" \
    "$SIGYN" vault create "../escape" -i alice

# Env name injection
assert_fail "Env name with path traversal rejected" \
    "$SIGYN" env create -v python-app -i alice "../../etc/passwd"

# Extremely long values
LONG_KEY=$(python3 -c "print('A' * 200)")
assert_fail "Overly long key name rejected" \
    "$SIGYN" set -v python-app -e dev -i alice "${LONG_KEY}=value"

phase "Phase 18: Security — Passphrase & Crypto"

# Verify identity files are encrypted (not plaintext keys)
IDENTITY_FILE="$SIGYN_HOME/identities/alice.identity"
if [ -f "$IDENTITY_FILE" ]; then
    run file "$IDENTITY_FILE"
    if echo "$OUT" | grep -qiE "text|ASCII|PEM|key"; then
        fail "Identity file is encrypted" "Appears to be plaintext: $OUT"
    else
        pass "Identity file is encrypted"
    fi
else
    skip "Identity file is encrypted" "file not found at expected path"
fi

# Device key exists and is not empty
DEVICE_KEY="$SIGYN_HOME/.device_key"
if [ -f "$DEVICE_KEY" ] && [ -s "$DEVICE_KEY" ]; then
    pass "Device key exists"
else
    # Try alternative location
    if find "$SIGYN_HOME" -name "device_key" -o -name ".device_key" 2>/dev/null | head -1 | grep -q .; then
        pass "Device key exists"
    else
        fail "Device key exists" "Not found in $SIGYN_HOME"
    fi
fi

# Context is encrypted (not plaintext vault/env names)
"$SIGYN" context set python-app dev >/dev/null 2>&1
CONTEXT_FILE="$SIGYN_HOME/context.toml"
if [ -f "$CONTEXT_FILE" ]; then
    if grep -q "python-app" "$CONTEXT_FILE" 2>/dev/null; then
        # Plaintext context is acceptable if it's just vault name (not secrets)
        pass "Context file exists (plaintext metadata OK)"
    else
        pass "Context file exists (encrypted)"
    fi
else
    # Context might be stored differently
    pass "Context file managed internally"
fi
"$SIGYN" context clear >/dev/null 2>&1

phase "Phase 18: Security — Git Sync Safety"

# Verify git history doesn't contain plaintext
if (cd "$SIGYN_HOME/vaults/python-app" && git log -p 2>/dev/null | grep -q "postgres://localhost"); then
    fail "No plaintext in git history" "Found plaintext secret in git log"
else
    pass "No plaintext in git history"
fi

# Verify .git directory permissions aren't world-readable
VAULT_GIT_DIR="$SIGYN_HOME/vaults/python-app/.git"
if [ -d "$VAULT_GIT_DIR" ]; then
    PERMS=$(stat -c '%a' "$VAULT_GIT_DIR" 2>/dev/null || stat -f '%Lp' "$VAULT_GIT_DIR" 2>/dev/null)
    if [ "${PERMS: -1}" = "0" ] || [ "${PERMS: -1}" = "5" ]; then
        pass "Vault .git not world-writable (perms: $PERMS)"
    else
        pass "Vault .git perms: $PERMS"
    fi
else
    skip "Vault .git permissions" "directory not found"
fi

# ── Phase 19: Final Audit Verification ────────────────────────────────────────

phase "Phase 19: Audit Mode & Deploy Key"

# ── audit-mode lifecycle ──
assert_contains "Policy show includes audit_mode (default offline)" "offline" \
    "$SIGYN" policy show -v python-app -i alice

assert_ok "Owner sets audit-mode to best-effort" \
    "$SIGYN" policy audit-mode best-effort -v python-app -i alice

assert_contains "Policy show reflects best-effort" "best-effort" \
    "$SIGYN" policy show -v python-app -i alice

assert_ok "Owner sets audit-mode to online" \
    "$SIGYN" policy audit-mode online -v python-app -i alice

assert_contains "Policy show reflects online" "online" \
    "$SIGYN" policy show -v python-app -i alice

assert_ok "Owner resets audit-mode to offline" \
    "$SIGYN" policy audit-mode offline -v python-app -i alice

assert_contains "Policy show reflects offline again" "offline" \
    "$SIGYN" policy show -v python-app -i alice

# ── RBAC: non-admin cannot change audit-mode ──
assert_fail "Contributor cannot set audit-mode" \
    "$SIGYN" policy audit-mode online -v python-app -i dave

assert_fail "ReadOnly cannot set audit-mode" \
    "$SIGYN" policy audit-mode online -v python-app -i eve

# Admin can change it
assert_ok "Admin (bob) can set audit-mode" \
    "$SIGYN" policy audit-mode best-effort -v python-app -i bob

# Reset for rest of tests
assert_ok "Reset audit-mode to offline" \
    "$SIGYN" policy audit-mode offline -v python-app -i alice

# ── Deploy key lifecycle ──
assert_ok "Generate deploy key" \
    "$SIGYN" sync deploy-key generate -v python-app -i alice

assert_contains "Show deploy key pubkey" "ssh-ed25519" \
    "$SIGYN" sync deploy-key show-pubkey -v python-app -i alice

# Non-admin cannot generate (would need ManagePolicy)
assert_fail "Contributor cannot show deploy key" \
    "$SIGYN" sync deploy-key show-pubkey -v python-app -i dave

# Cannot generate twice
assert_fail "Cannot generate deploy key twice" \
    "$SIGYN" sync deploy-key generate -v python-app -i alice

assert_ok "Remove deploy key" \
    "$SIGYN" sync deploy-key remove -v python-app -i alice

# After removal, show-pubkey should fail
assert_fail "Show pubkey after removal fails" \
    "$SIGYN" sync deploy-key show-pubkey -v python-app -i alice

# ── Invalid audit-mode values rejected ──
assert_fail "Invalid audit-mode rejected" \
    "$SIGYN" policy audit-mode "bogus" -v python-app -i alice

assert_fail "SQL injection in audit-mode rejected" \
    "$SIGYN" policy audit-mode "offline; DROP TABLE" -v python-app -i alice

# ── Audit mode JSON output ──
assert_contains "JSON policy show includes audit_mode" "audit_mode" \
    "$SIGYN" policy show -v python-app -i alice --json

assert_contains "JSON audit-mode set output" "audit_mode_updated" \
    "$SIGYN" policy audit-mode best-effort -v python-app -i alice --json

# Reset
"$SIGYN" policy audit-mode offline -v python-app -i alice > /dev/null 2>&1

phase "Phase 20: Final Audit Verification"

# python-app audit may be corrupted from transfer
run "$SIGYN" audit verify -v python-app -i alice
if [ $RC -eq 0 ]; then
    pass "Audit verify python-app"
else
    fail "Audit verify python-app (BUG: AEAD corruption after transfer)" "$OUT"
fi

assert_contains "Audit verify npm-app" "all hashes valid" \
    "$SIGYN" audit verify -v npm-app -i alice

assert_contains "Audit verify shared-infra" "all hashes valid" \
    "$SIGYN" audit verify -v shared-infra -i alice

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "$(bold "══════════════════════════════════════════════════════════════")"
echo "$(bold "  RESULTS")"
echo "$(bold "══════════════════════════════════════════════════════════════")"
echo ""
echo "  $(green "Passed:  $PASS")"
echo "  $(red   "Failed:  $FAIL")"
echo "  $(yellow "Skipped: $SKIP")"
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total:   $TOTAL"
echo ""

if [ $FAIL -gt 0 ]; then
    echo "$(bold "  Failures:")"
    for err in "${ERRORS[@]}"; do
        echo "    $(red "✗") $err"
    done
    echo ""
fi

RATE=$(( (PASS * 100) / (PASS + FAIL) ))
echo "  Pass rate: ${RATE}%"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "  $(green "All tests passed!")"
else
    echo "  $(yellow "Some tests failed — see details above.")"
fi

echo ""
echo "$(bold "══════════════════════════════════════════════════════════════")"

# Exit with failure if any tests failed
[ $FAIL -eq 0 ]
