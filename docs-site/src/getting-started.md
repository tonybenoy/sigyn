# Getting Started with Sigyn

A step-by-step guide to installing Sigyn, creating your first vault, managing secrets,
collaborating with team members, and syncing via git.

## Install

### One-liner (recommended)

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.ps1 | iex
```

This downloads the latest pre-built binary for your platform and adds it to your PATH.
Falls back to building from source if no pre-built binary is available.

### From source

Requires Rust 1.75+ and git:

```bash
cargo install --git https://github.com/tonybenoy/sigyn.git --bin sigyn sigyn-cli
cargo install --git https://github.com/tonybenoy/sigyn.git --bin sigyn-recovery sigyn-recovery
```

Or clone and build locally:

```bash
git clone https://github.com/tonybenoy/sigyn.git
cd sigyn
cargo build --release
cp target/release/sigyn target/release/sigyn-recovery ~/.local/bin/
```

### Verify

```bash
sigyn --version
```

### Uninstall

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/uninstall.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/tonybenoy/sigyn/main/uninstall.ps1 | iex
```

## Quick Setup (Guided Wizard)

The fastest way to get started is the onboard wizard, which walks you through
everything below in one interactive flow:

```bash
sigyn onboard
```

Or use `sigyn init` for a lighter-weight setup that offers to create an identity
and vault if none exist.

If you prefer to do each step manually, read on.

## Create an Identity

An identity is your cryptographic keypair (X25519 for encryption, Ed25519 for signing).
All vault operations require one.

```bash
sigyn identity create --name alice
```

You will be prompted for a passphrase (minimum 8 characters). This passphrase protects
your private keys at rest via Argon2id. Remember it -- there is no recovery without
it (or Shamir shards).

Output:

```
Identity 'alice' created
  Fingerprint: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  Store this fingerprint -- others will use it to share secrets with you.
```

Verify it was created:

```bash
sigyn identity list
```

Show full details:

```bash
sigyn identity show alice
```

## Enable MFA (Optional)

Add TOTP-based multi-factor authentication to your identity for an extra layer of
security. You'll need an authenticator app (Google Authenticator, Authy, 1Password,
etc.).

```bash
sigyn mfa setup -i alice
```

This will:

1. Generate a TOTP secret and display a **QR code** in the terminal (plus the base32 secret for manual entry).
2. Ask you to enter a code from your authenticator app to verify.
3. Print 8 single-use backup codes — **save these somewhere safe**.

Once enrolled, any vault policy that sets `require_mfa: true` will prompt for a TOTP
code before granting access. A session-based grace period (default: 1 hour) avoids
re-prompting on every operation.

Check your enrollment status at any time:

```bash
sigyn mfa status -i alice
```

## Set Defaults

Configure your default identity and vault to avoid typing `--identity` and `--vault`
on every command:

```bash
sigyn init --identity alice
```

This creates `~/.sigyn/config.toml` with your defaults.

For per-project defaults, run `project init` in your project root:

```bash
sigyn project init
```

This interactively creates a `.sigyn.toml` with your vault and identity:

```toml
[project]
vault = "myapp"
env = "dev"
identity = "alice"

[commands]
# dev = "npm run dev"
# app = "./start-server"
```

Uncomment and edit the `[commands]` section to add named run commands.
With this file, most commands need no flags at all. Use `--global` to write
to `~/.sigyn/project.toml` instead (for defaults you don't want in a repo).

## Create a Vault

A vault is an encrypted container for secrets, organized by environment:

```bash
sigyn vault create myapp
```

This generates a random 256-bit master key, seals it to your identity via X25519
envelope encryption, and creates three default environments: `dev`, `staging`, `prod`.

```bash
sigyn vault info myapp
```

Output:

```
Vault Info
  Name:         myapp
  ID:           6ba7b810-9dad-11d1-80b4-00c04fd430c8
  Owner:        a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  Environments: dev, staging, prod
  Created:      2026-02-23 14:30:00 UTC
```

Set it as your default vault:

```bash
sigyn init --identity alice --vault myapp
```

## Add Secrets

Store a secret in the `dev` environment:

```bash
sigyn secret set DATABASE_URL 'postgres://user:pass@localhost:5432/mydb' --env dev
```

Add more secrets:

```bash
sigyn secret set API_KEY 'sk-dev-abc123' --env dev
sigyn secret set REDIS_URL 'redis://localhost:6379' --env dev
```

Generate a random secret:

```bash
sigyn secret generate JWT_SECRET --env dev --length 64
```

Read from stdin (useful for multiline values or piping):

```bash
cat certificate.pem | sigyn secret set TLS_CERT --env dev
```

## Read Secrets

Retrieve a secret value:

```bash
sigyn secret get DATABASE_URL --env dev
```

Output:

```
postgres://user:pass@localhost:5432/mydb
```

Get structured output with metadata:

```bash
sigyn secret get DATABASE_URL --env dev --json
```

## List Secrets

List all keys in an environment (values hidden by default):

```bash
sigyn secret list --env dev
```

Reveal values:

```bash
sigyn secret list --env dev --reveal
```

## Run with Injected Secrets

Launch a process with all secrets from an environment injected as environment variables.
The `exec` subcommand is the default, so you can omit it:

```bash
sigyn run -e dev -- ./my-app
```

The secrets are passed directly to the child process environment. They are never
written to disk in plaintext.

Use `-c` / `--clean` to avoid inheriting the parent shell's environment:

```bash
sigyn run -e dev -c -- node server.js
```

Use `--prod` or `--staging` as environment shortcuts:

```bash
sigyn run --prod -- docker compose up
```

If you have a `.sigyn.toml` with named commands, run them directly:

```bash
sigyn run dev       # runs the 'dev' command from [commands] table
```

## Export to Dotenv

Export secrets in `.env` format:

```bash
sigyn run export --env dev --format dotenv > .env
```

Other supported formats: `json`, `shell`, `docker`, `k8s`.

```bash
# Kubernetes secret manifest
sigyn run export --env prod --format k8s --name my-app-secrets > secret.yaml
```

## Import from .env

Import an existing `.env` file into a vault:

```bash
sigyn import dotenv .env --env dev
```

Import from a JSON file (expects a flat key-value object):

```bash
sigyn import json secrets.json --env dev
```

Import from cloud providers:

```bash
sigyn import aws --secret-id myapp/dev --env dev
sigyn import doppler --project myapp --config dev --env dev
sigyn import gcp --project my-gcp-project --secret db-password --env prod
sigyn import 1password --vault "Dev Secrets" --item "API Keys" --env dev
```

## Invite a Team Member

First, your teammate creates their own identity on their machine:

```bash
# On Bob's machine:
sigyn identity create --name bob
sigyn identity list    # note the fingerprint
```

Bob shares their fingerprint with you out-of-band (chat, email, etc.).

Add Bob to the vault policy with a role and environment restrictions:

```bash
sigyn policy member-add <bob-fingerprint> --role contributor --envs dev,staging
```

Or create a signed invitation file for a more formal flow:

```bash
sigyn delegation invite create --role contributor --envs dev,staging
```

Share the resulting JSON file with Bob.

## Accept an Invitation

Bob accepts the invitation on his machine:

```bash
# On Bob's machine:
sigyn delegation invite accept ./invitation-abc123.json
```

The invitation's Ed25519 signature is verified before acceptance. Once accepted,
Bob's X25519 public key is added to the vault envelope, allowing him to decrypt
secrets in the allowed environments.

## View the Delegation Tree

See who has access and who invited whom:

```bash
sigyn delegation tree
```

Output:

```
alice (a1b2c3d4...) [owner]
  bob (e5f6a7b8...) [contributor]
```

## Create Environments

Vaults start with `dev`, `staging`, and `prod`. Add more as needed:

```bash
sigyn env create qa
sigyn env create canary
```

List environments:

```bash
sigyn env list
```

## Promote Secrets

Copy secrets from one environment to another:

```bash
sigyn env promote --from dev --to staging
```

Promote specific keys only:

```bash
sigyn env promote --from staging --to prod --keys DATABASE_URL,API_KEY
```

Then update production values to their real credentials:

```bash
sigyn secret set DATABASE_URL 'postgres://user:pass@prod-host/myapp' --env prod
```

## Sync via Git

Sigyn vaults are directories of encrypted files that can be synced through git. All
data is encrypted at rest, so syncing never exposes secrets.

Configure sync for a vault:

```bash
sigyn sync configure --remote-url git@github.com:team/secrets.git
```

Push local changes:

```bash
sigyn sync push
```

Pull remote changes:

```bash
sigyn sync pull
```

Check sync status:

```bash
sigyn sync status
```

On another machine (or as another team member):

```bash
sigyn sync pull --vault myapp
```

## Audit Trail

Every operation is recorded in a hash-chained, Ed25519-signed audit log.

View recent entries:

```bash
sigyn audit tail
sigyn audit tail -n 50
```

Verify the chain has not been tampered with:

```bash
sigyn audit verify
```

Query by actor or environment:

```bash
sigyn audit query --actor a1b2c3d4... --env prod
```

Export the full log:

```bash
sigyn audit export --output audit.json --format json
```

Add a witness countersignature:

```bash
sigyn audit witness
```

## Shell Completions

Generate completions for your shell:

```bash
# Bash
sigyn completions bash > ~/.local/share/bash-completion/completions/sigyn

# Zsh
sigyn completions zsh > ~/.zfunc/_sigyn

# Fish
sigyn completions fish > ~/.config/fish/completions/sigyn.fish
```

Restart your shell or source the file to activate completions.

## Next Steps

- [CLI Reference](cli-reference.md) -- complete command documentation
- [Security Model](security.md) -- cryptographic primitives, MFA, and threat model
- [Delegation](delegation.md) -- invitation flow and cascade revocation
- [Sync](sync.md) -- conflict resolution and CRDT merge
- Set up [Shamir recovery shards](security.md#shamir-secret-sharing-recovery) for disaster recovery:

```bash
sigyn-recovery split --identity alice --threshold 3 --total 5
```
