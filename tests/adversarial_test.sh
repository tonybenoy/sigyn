#!/usr/bin/env bash
# Sigyn Adversarial Security Test
# Simulates a malicious actor attempting to break vault security.
#
# Usage:
#   bash tests/adversarial_test.sh [path-to-sigyn-binary]
#
# Requires: python3 (for bit-flip tampering)
# Runs in an isolated /tmp directory — no side effects on your real vaults.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
S="${1:-$REPO_DIR/target/release/sigyn}"
BASE="/tmp/sigyn-adversarial-$$"
rm -rf "$BASE"; mkdir -p "$BASE"

if [ ! -x "$S" ]; then
    echo "Binary not found: $S"
    echo "Build first: cargo build --release"
    exit 1
fi

PASS=0; FAIL=0; FINDINGS=()
green() { printf "\033[0;32m  ✓ DEFENDED: %s\033[0m\n" "$*"; }
red()   { printf "\033[0;31m  ✗ BREACHED: %s\033[0m\n" "$*"; }
yellow(){ printf "\033[0;33m  ⚠ NOTE: %s\033[0m\n" "$*"; }
bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
defended() { PASS=$((PASS+1)); green "$1"; }
breached() { FAIL=$((FAIL+1)); FINDINGS+=("$1"); red "$1"; }

cleanup() { rm -rf "$BASE"; }
trap cleanup EXIT

# ── SETUP ──
bold "═══ SETUP ═══"
export SIGYN_HOME="$BASE/home"
export SIGYN_PASSPHRASE="alice-pass-2026!"
$S identity create --name alice 2>&1>/dev/null
ALICE_FP=$($S identity show alice 2>&1|grep Fingerprint|awk '{print $2}')
$S vault create tv --env dev,staging,prod -i alice 2>&1>/dev/null
$S secret set DB_PASS "super-secret" -v tv -e dev -i alice 2>&1>/dev/null
$S secret set API_KEY "sk-live-123" -v tv -e prod -i alice 2>&1>/dev/null
$S secret set STG_TOK "stg-abc" -v tv -e staging -i alice 2>&1>/dev/null

export SIGYN_PASSPHRASE="bob-pass-2026!!"
$S identity create --name bob 2>&1>/dev/null
BOB_FP=$($S identity show bob 2>&1|grep Fingerprint|awk '{print $2}')
export SIGYN_PASSPHRASE="alice-pass-2026!"
$S delegation invite --pubkey "$BOB_FP" --role contributor --envs dev -v tv -i alice 2>&1>/dev/null
INV=$(ls -1t "$SIGYN_HOME/invitations/"*.json|head -1)
export SIGYN_PASSPHRASE="bob-pass-2026!!"
$S delegation accept "$INV" -i bob 2>&1>/dev/null

export SIGYN_PASSPHRASE="evil-pass-2026!!"
$S identity create --name mallory 2>&1>/dev/null

export SIGYN_PASSPHRASE="bob-pass-2026!!"
GOT=$($S secret get DB_PASS -v tv -e dev -i bob 2>&1)
[ "$GOT" = "super-secret" ] && echo "  Setup ✓" || { echo "SETUP FAIL: $GOT"; exit 1; }

VD="$SIGYN_HOME/vaults/tv"
EF="$VD/envs/dev.vault"

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 1: Unauthorized Access ═══"
export SIGYN_PASSPHRASE="evil-pass-2026!!"
OUT=$($S secret get DB_PASS -v tv -e dev -i mallory 2>&1||true)
echo "$OUT"|grep -q "super-secret" && breached "Rogue read" || defended "Rogue blocked"

export SIGYN_PASSPHRASE="wrong-guess"
OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
echo "$OUT"|grep -q "super-secret" && breached "Wrong pass" || defended "Wrong pass rejected"

export SIGYN_PASSPHRASE="bob-pass-2026!!"
OUT=$($S secret get API_KEY -v tv -e prod -i bob 2>&1||true)
echo "$OUT"|grep -q "sk-live-123" && breached "Bob read prod" || defended "Bob blocked from prod"

OUT=$($S secret get STG_TOK -v tv -e staging -i bob 2>&1||true)
echo "$OUT"|grep -q "stg-abc" && breached "Bob read staging" || defended "Bob blocked from staging"

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 2: File Tampering ═══"
export SIGYN_PASSPHRASE="alice-pass-2026!"

for tf in vault.toml members.cbor policy.cbor; do
    F="$VD/$tf"; [ ! -f "$F" ] && continue
    cp "$F" "$F.bak"
    python3 -c "d=bytearray(open('$F','rb').read());d[len(d)//2]^=0xFF;open('$F','wb').write(d)"
    OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
    cp "$F.bak" "$F"
    echo "$OUT"|grep -q "super-secret" && breached "Tampered $tf" || defended "Tampered $tf rejected"
done

if [ -f "$EF" ]; then
    cp "$EF" "$EF.bak"
    python3 -c "d=bytearray(open('$EF','rb').read());d[len(d)//2]^=0xFF;open('$EF','wb').write(d)"
    OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
    cp "$EF.bak" "$EF"
    echo "$OUT"|grep -q "super-secret" && breached "Tampered env" || defended "Tampered env rejected"
fi

cp "$VD/vault.toml" "$VD/vault.toml.bak"
dd if=/dev/zero of="$VD/vault.toml" bs=1 count=256 2>/dev/null
OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
cp "$VD/vault.toml.bak" "$VD/vault.toml"
echo "$OUT"|grep -q "super-secret" && breached "Zeroed manifest" || defended "Zeroed manifest rejected"

cp "$VD/members.cbor" "$VD/members.cbor.bak"
dd if="$VD/members.cbor.bak" of="$VD/members.cbor" bs=1 count=10 2>/dev/null
OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
cp "$VD/members.cbor.bak" "$VD/members.cbor"
echo "$OUT"|grep -q "super-secret" && breached "Truncated header" || defended "Truncated header rejected"

if [ -f "$EF" ]; then
    cp "$EF" "$EF.bak"
    echo "JUNK" >> "$EF"
    OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
    cp "$EF.bak" "$EF"
    echo "$OUT"|grep -q "super-secret" && breached "Trailing junk env" || defended "Trailing junk env rejected"
fi

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 3: Privilege Escalation ═══"
export SIGYN_PASSPHRASE="bob-pass-2026!!"
OUT=$($S delegation invite --pubkey "$ALICE_FP" --role admin --envs '*' -v tv -i bob 2>&1||true)
echo "$OUT"|grep -qi "Invited" && breached "Contributor invited" || defended "Contributor cannot invite"

OUT=$($S delegation revoke "$ALICE_FP" -v tv -i bob 2>&1||true)
echo "$OUT"|grep -qi "Revoked" && breached "Contributor revoked owner!" || defended "Contributor cannot revoke"

OUT=$($S secret set HACK "x" -v tv -e prod -i bob 2>&1||true)
echo "$OUT"|grep -q "Set" && breached "Contributor wrote prod" || defended "Contributor blocked from prod"

export SIGYN_PASSPHRASE="evil-pass-2026!!"
OUT=$($S secret set HACK "x" -v tv -e dev -i mallory 2>&1||true)
echo "$OUT"|grep -q "Set" && breached "Non-member wrote" || defended "Non-member cannot write"

OUT=$($S secret list -v tv -e dev -i mallory 2>&1||true)
echo "$OUT"|grep -q "DB_PASS" && breached "Non-member listed" || defended "Non-member cannot list"

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 4: Stolen Files ═══"
AH="$BASE/attacker"; mkdir -p "$AH/vaults"
cp -r "$VD" "$AH/vaults/tv"
export SIGYN_HOME="$AH"; export SIGYN_PASSPHRASE="evil-pass-2026!!"
$S identity create --name attacker 2>&1>/dev/null
OUT=$($S secret get DB_PASS -v tv -e dev -i attacker 2>&1||true)
echo "$OUT"|grep -q "super-secret" && breached "Stolen vault read!" || defended "Stolen vault useless"

cp -r "$BASE/home/identities" "$AH/" 2>/dev/null||true
export SIGYN_PASSPHRASE="wrong-pass"
OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
echo "$OUT"|grep -q "super-secret" && breached "Wrong pass on stolen ID!" || defended "Stolen ID needs passphrase"
export SIGYN_HOME="$BASE/home"

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 5: Replay & Fake Invitations ═══"
export SIGYN_PASSPHRASE="evil-pass-2026!!"
OUT=$($S delegation accept "$INV" -i mallory 2>&1||true)
if echo "$OUT"|grep -qi "accepted"; then
    OUT2=$($S secret get DB_PASS -v tv -e dev -i mallory 2>&1||true)
    echo "$OUT2"|grep -q "super-secret" && breached "Replay gave access!" || defended "Replay no access"
else defended "Replay rejected"; fi

cp "$INV" /tmp/tampered-inv-$$.json
sed -i 's/contributor/admin/g' /tmp/tampered-inv-$$.json 2>/dev/null
OUT=$($S delegation accept /tmp/tampered-inv-$$.json -i mallory 2>&1||true)
echo "$OUT"|grep -qi "accepted.*admin" && breached "Tampered invite!" || defended "Tampered invite rejected"
rm -f /tmp/tampered-inv-$$.json

echo '{"id":"fake"}' > /tmp/fake-inv-$$.json
OUT=$($S delegation accept /tmp/fake-inv-$$.json -i mallory 2>&1||true)
echo "$OUT"|grep -qi "accepted" && breached "Fake invite accepted!" || defended "Fake invite rejected"
rm -f /tmp/fake-inv-$$.json

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 6: Audit Attacks ═══"
export SIGYN_PASSPHRASE="alice-pass-2026!"
AF="$VD/audit.log.json"

if [ -f "$AF" ]; then
    cp "$AF" "$AF.bak"; rm "$AF"
    OUT=$($S audit verify -v tv -i alice 2>&1||true)
    cp "$AF.bak" "$AF"
    echo "$OUT"|grep -qi "error\|fail\|broken" && defended "Missing audit detected" || yellow "Deleted audit silently reports 0 (no external checkpoint)"

    cp "$AF" "$AF.bak"
    python3 -c "d=bytearray(open('$AF','rb').read());d[len(d)//2]^=0xFF;open('$AF','wb').write(d)"
    OUT=$($S audit verify -v tv -i alice 2>&1||true)
    cp "$AF.bak" "$AF"
    echo "$OUT"|grep -qi "error\|fail\|broken" && defended "Corrupted audit detected" || breached "Corrupted audit accepted"
fi

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 7: Path Traversal & Symlinks ═══"
ln -sf /etc/passwd "$BASE/home/vaults/evil-link" 2>/dev/null
OUT=$($S secret list -v evil-link -e dev -i alice 2>&1||true)
rm -f "$BASE/home/vaults/evil-link"
echo "$OUT"|grep -q "root:" && breached "Symlink traversal!" || defended "Symlink blocked"

OUT=$($S secret get x -v "../../etc/passwd" -e dev -i alice 2>&1||true)
echo "$OUT"|grep -q "root:" && breached "Path traversal!" || defended "Path traversal blocked"

OUT=$($S secret get x -v tv -e "../../etc/passwd" -i alice 2>&1||true)
echo "$OUT"|grep -q "root:" && breached "Env path traversal!" || defended "Env path traversal blocked"

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 8: Crypto & Leakage ═══"
FOUND=0; grep -rl "super-secret\|sk-live-123" "$VD" 2>/dev/null && FOUND=1
[ "$FOUND" -eq 1 ] && breached "Plaintext in files!" || defended "No plaintext in files"

FOUND=0; grep -rl "BEGIN PRIVATE\|PRIVATE KEY" "$BASE/home/identities" 2>/dev/null && FOUND=1
[ "$FOUND" -eq 1 ] && breached "Plaintext keys!" || defended "Identity encrypted"

OUT=$($S run -v tv -e dev -i alice -- env 2>&1||true)
echo "$OUT"|grep -q "SIGYN_PASSPHRASE=" && breached "Passphrase leaked to child!" || defended "Passphrase scrubbed from child"

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 9: Cross-Vault Attacks ═══"
$S vault create decoy --env dev -i alice 2>&1>/dev/null
$S secret set X "decoy" -v decoy -e dev -i alice 2>&1>/dev/null
DD="$SIGYN_HOME/vaults/decoy"

cp "$VD/members.cbor" "$VD/members.cbor.bak"
cp "$DD/members.cbor" "$VD/members.cbor"
OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
cp "$VD/members.cbor.bak" "$VD/members.cbor"
echo "$OUT"|grep -q "super-secret" && breached "Cross-vault header!" || defended "Cross-vault header rejected"

cp "$VD/policy.cbor" "$VD/policy.cbor.bak"
cp "$DD/policy.cbor" "$VD/policy.cbor"
OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
cp "$VD/policy.cbor.bak" "$VD/policy.cbor"
echo "$OUT"|grep -q "super-secret" && breached "Cross-vault policy!" || defended "Cross-vault policy rejected"

if [ -f "$EF" ] && [ -f "$DD/envs/dev.vault" ]; then
    cp "$EF" "$EF.bak"
    cp "$DD/envs/dev.vault" "$EF"
    OUT=$($S secret get DB_PASS -v tv -e dev -i alice 2>&1||true)
    cp "$EF.bak" "$EF"
    echo "$OUT"|grep -q "super-secret" && breached "Cross-vault env!" || defended "Cross-vault env rejected"
fi

# ══════════════════════════════════════════════════════════
echo ""
bold "═══ 10: Post-Revocation ═══"
mkdir -p "$BASE/pre-revoke"; cp -r "$VD" "$BASE/pre-revoke/tv"
export SIGYN_PASSPHRASE="alice-pass-2026!"
$S delegation revoke "$BOB_FP" -v tv -i alice 2>&1>/dev/null

export SIGYN_PASSPHRASE="bob-pass-2026!!"
OUT=$($S secret get DB_PASS -v tv -e dev -i bob 2>&1||true)
echo "$OUT"|grep -q "super-secret" && breached "Revoked member read!" || defended "Revoked member blocked"

OUT=$($S secret set HACK "x" -v tv -e dev -i bob 2>&1||true)
echo "$OUT"|grep -q "Set" && breached "Revoked member wrote!" || defended "Revoked member cannot write"

# ══════════════════════════════════════════════════════════
echo ""
bold "══════════════════════════════════════════════════════════"
bold "  ADVERSARIAL TEST RESULTS"
bold "══════════════════════════════════════════════════════════"
echo ""
green "  Defended:  $PASS"
if [ "$FAIL" -gt 0 ]; then
    red "  Breached:  $FAIL"
else
    green "  Breached:  0"
fi
echo "  Total:     $((PASS+FAIL))"
echo ""
if [ ${#FINDINGS[@]} -gt 0 ]; then
    bold "  Vulnerabilities:"; for f in "${FINDINGS[@]}"; do red "    ✗ $f"; done; echo ""
fi
[ "$FAIL" -eq 0 ] && green "  ★ ALL ATTACKS DEFENDED" || red "  $FAIL vulnerability(ies) found"
bold "══════════════════════════════════════════════════════════"
exit "$FAIL"
