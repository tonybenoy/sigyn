#!/bin/bash
# Sigyn Secrets — Bitbucket Pipe
#
# Decrypt and inject secrets from a Sigyn vault into your Bitbucket Pipeline.
#
# Required variables:
#   SIGYN_CI_BUNDLE    — output of `sigyn ci setup` (base64-encoded JSON)
#   SIGYN_PASSPHRASE   — CI identity passphrase
#   VAULT_SSH_KEY      — SSH private key for cloning the vault repo
#   VAULT_REPO         — Git URL for the vault repository
#   VAULT              — Vault name
#   ENVIRONMENT        — Environment name (e.g. dev, staging, prod)
#
# Optional variables:
#   EXPORT_MODE        — env, dotenv, json (default: dotenv)
#   DOTENV_PATH        — Output path for dotenv/json export (default: .env)
#   KEYS               — Comma-separated list of specific keys to export
#   VERSION            — Sigyn version to install (default: latest)

set -euo pipefail

# ── Helpers ────────────────────────────────────────────────────────────────
info()    { echo "INFO: $*"; }
error()   { echo "ERROR: $*" >&2; exit 1; }
success() { echo "✔ $*"; }

# ── Validate required variables ───────────────────────────────────────────
[ -z "${SIGYN_CI_BUNDLE:-}" ]  && error "SIGYN_CI_BUNDLE is required"
[ -z "${SIGYN_PASSPHRASE:-}" ] && error "SIGYN_PASSPHRASE is required"
[ -z "${VAULT_SSH_KEY:-}" ]    && error "VAULT_SSH_KEY is required"
[ -z "${VAULT_REPO:-}" ]       && error "VAULT_REPO is required"
[ -z "${VAULT:-}" ]            && error "VAULT is required"
[ -z "${ENVIRONMENT:-}" ]      && error "ENVIRONMENT is required"

# ── Defaults ──────────────────────────────────────────────────────────────
EXPORT_MODE="${EXPORT_MODE:-dotenv}"
DOTENV_PATH="${DOTENV_PATH:-.env}"
KEYS="${KEYS:-}"
VERSION="${VERSION:-latest}"
SIGYN_HOME="${SIGYN_HOME:-$HOME/.sigyn}"

# ── Validate inputs ──────────────────────────────────────────────────────
if ! echo "$VAULT" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9._-]*$'; then
  error "Invalid vault name: must be alphanumeric with hyphens/underscores only"
fi

case "$DOTENV_PATH" in
  /*) error "DOTENV_PATH must be a relative path" ;;
  *../*) error "DOTENV_PATH must not contain '..'" ;;
esac

# ── Cleanup trap ──────────────────────────────────────────────────────────
cleanup() {
  rm -rf "$SIGYN_HOME/identities" "$SIGYN_HOME/.device_key" "$SIGYN_HOME/vaults" \
    ~/.ssh/sigyn_vault_key 2>/dev/null || true
  info "Cleanup complete"
}
trap cleanup EXIT

# ── Install Sigyn ─────────────────────────────────────────────────────────
info "Installing Sigyn ${VERSION}..."
export SIGYN_VERSION="$VERSION"
INSTALL_URL="${SIGYN_INSTALL_URL:-https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh}"
curl -fsSL "$INSTALL_URL" | sh
export PATH="$HOME/.sigyn/bin:$PATH"
success "Sigyn installed"

# ── Restore identity from bundle ──────────────────────────────────────────
info "Restoring CI identity..."
BUNDLE_JSON=$(echo "$SIGYN_CI_BUNDLE" | base64 -d)
FINGERPRINT=$(echo "$BUNDLE_JSON" | jq -r '.fingerprint')
IDENTITY_B64=$(echo "$BUNDLE_JSON" | jq -r '.identity')
DEVICE_KEY_B64=$(echo "$BUNDLE_JSON" | jq -r '.device_key')

if ! echo "$FINGERPRINT" | grep -qE '^[a-f0-9]{16,64}$'; then
  error "Invalid fingerprint format in CI bundle"
fi

mkdir -p "$SIGYN_HOME/identities"
echo "$IDENTITY_B64" | base64 -d > "$SIGYN_HOME/identities/${FINGERPRINT}.identity"
chmod 600 "$SIGYN_HOME/identities/${FINGERPRINT}.identity"
echo "$DEVICE_KEY_B64" | base64 -d > "$SIGYN_HOME/.device_key"
chmod 400 "$SIGYN_HOME/.device_key"
success "Identity restored (${FINGERPRINT:0:16}...)"

# ── Clone vault ───────────────────────────────────────────────────────────
info "Cloning vault repository..."
mkdir -p ~/.ssh
echo "$VAULT_SSH_KEY" > ~/.ssh/sigyn_vault_key
chmod 600 ~/.ssh/sigyn_vault_key
export GIT_SSH_COMMAND="ssh -i ~/.ssh/sigyn_vault_key -o StrictHostKeyChecking=yes"

# Pre-fetch host keys
if echo "$VAULT_REPO" | grep -q "github.com"; then
  ssh-keyscan -t ed25519,rsa github.com >> ~/.ssh/known_hosts 2>/dev/null
elif echo "$VAULT_REPO" | grep -q "gitlab.com"; then
  ssh-keyscan -t ed25519,rsa gitlab.com >> ~/.ssh/known_hosts 2>/dev/null
elif echo "$VAULT_REPO" | grep -q "bitbucket.org"; then
  ssh-keyscan -t ed25519,rsa bitbucket.org >> ~/.ssh/known_hosts 2>/dev/null
fi

VAULT_DIR="$SIGYN_HOME/vaults/$VAULT"
if [ -d "$VAULT_DIR/.git" ]; then
  git -C "$VAULT_DIR" pull --ff-only
else
  mkdir -p "$SIGYN_HOME/vaults"
  git clone "$VAULT_REPO" "$VAULT_DIR"
fi

rm -f ~/.ssh/sigyn_vault_key
success "Vault cloned"

# ── Export secrets ────────────────────────────────────────────────────────
info "Exporting secrets (mode: $EXPORT_MODE)..."
export SIGYN_PASSPHRASE
RAW_JSON=$("$HOME/.sigyn/bin/sigyn" run export \
  --vault "$VAULT" \
  --env "$ENVIRONMENT" \
  --identity "$FINGERPRINT" \
  --format json 2>/dev/null)

# Filter to specific keys if requested
if [ -n "$KEYS" ]; then
  FILTER=$(echo "$KEYS" | tr ',' '\n' | jq -R . | jq -s '.')
  RAW_JSON=$(echo "$RAW_JSON" | jq --argjson keys "$FILTER" \
    'to_entries | map(select(.key as $k | $keys | index($k))) | from_entries')
fi

COUNT=$(echo "$RAW_JSON" | jq 'length')

case "$EXPORT_MODE" in
  env)
    # Export to Bitbucket's BASH_ENV-like mechanism
    echo "$RAW_JSON" | jq -r 'to_entries[] | "export \(.key)=\u0027\(.value)\u0027"' >> "${BASH_ENV:-/dev/null}"
    # Also write a dotenv for sourcing
    echo "$RAW_JSON" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > sigyn.env
    success "Exported $COUNT secrets to environment"
    ;;
  dotenv)
    echo "$RAW_JSON" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > "$DOTENV_PATH"
    success "Exported $COUNT secrets to $DOTENV_PATH"
    ;;
  json)
    echo "$RAW_JSON" > "$DOTENV_PATH"
    success "Exported $COUNT secrets as JSON to $DOTENV_PATH"
    ;;
  *)
    error "Unknown export mode: $EXPORT_MODE (use: env, dotenv, json)"
    ;;
esac
