# Getting Started with Sigyn

A step-by-step guide to installing Sigyn, creating your first vault, managing secrets,
collaborating with team members, and syncing via git.

## Prerequisites

- Rust 1.75 or later (`rustup` recommended)
- git (for sync features)

## Install from Source

Clone the repository and build:

```bash
git clone https://github.com/your-org/sigyn.git
cd sigyn
cargo build --release
```

The build produces two binaries:

```bash
# Main CLI
cp target/release/sigyn ~/.local/bin/

# Standalone recovery tool
cp target/release/sigyn-recovery ~/.local/bin/
```

Alternatively, install directly via Cargo:

```bash
cargo install --path crates/sigyn-cli
cargo install --path crates/sigyn-recovery
```

Verify the installation:

```bash
sigyn --version
```

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

## Set Defaults

Configure your default identity and vault to avoid typing `--identity` and `--vault`
on every command:

```bash
sigyn init --identity alice
```

This creates `~/.sigyn/config.toml` with your defaults.

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

Launch a process with all secrets from an environment injected as environment variables:

```bash
sigyn run exec --env dev -- ./my-app
```

The secrets are passed directly to the child process environment. They are never
written to disk in plaintext.

Use `--clean` to avoid inheriting the parent shell's environment:

```bash
sigyn run exec --env dev --clean -- node server.js
```

For Docker:

```bash
sigyn run exec --env dev -- docker compose up
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
- [Security Model](security.md) -- cryptographic primitives and threat model
- [Delegation](delegation.md) -- invitation flow and cascade revocation
- [Sync](sync.md) -- conflict resolution and CRDT merge
- Set up [Shamir recovery shards](security.md#shamir-secret-sharing-recovery) for disaster recovery:

```bash
sigyn-recovery split --identity alice --threshold 3 --total 5
```
