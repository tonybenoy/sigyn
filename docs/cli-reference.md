# Sigyn CLI Reference

Complete command reference for the `sigyn` binary.

```
sigyn <COMMAND> [OPTIONS]
```

## Global Flags

These flags can be used with any subcommand:

| Flag | Short | Description |
|---|---|---|
| `--vault <NAME>` | `-v` | Vault name (overrides default from config) |
| `--env <NAME>` | `-e` | Environment name (overrides default from config) |
| `--identity <NAME>` | `-i` | Identity name or fingerprint (overrides default) |
| `--json` | | Output as JSON |
| `--quiet` | | Suppress non-essential output |
| `--dry-run` | | Preview changes without applying |

**Resolution priority:** CLI flags > `.sigyn.toml` (project dir) > `~/.sigyn/project.toml` > `~/.sigyn/config.toml` > defaults.

## identity (alias: id)

Manage cryptographic identities (X25519 + Ed25519 keypairs).

### identity create

Create a new identity with a passphrase-protected keypair.

```bash
sigyn identity create --name alice
sigyn identity create --name alice --email alice@example.com
```

| Flag | Short | Description |
|---|---|---|
| `--name <NAME>` | `-n` | Required. Name for this identity |
| `--email <EMAIL>` | `-E` | Optional email address |

Prompts for a passphrase (minimum 8 characters) with confirmation.

### identity list

List all identities on this machine.

```bash
sigyn identity list
sigyn id list --json
```

### identity show

Show details of a specific identity (name, email, fingerprint, creation date).

```bash
sigyn identity show alice
sigyn identity show                  # uses default identity
sigyn identity show a1b2c3d4...     # by fingerprint
```

### identity export

Export the public key portion of an identity for sharing with team members.

```bash
sigyn identity export --name alice > alice.pub
```

### identity import

Import a teammate's public key.

```bash
sigyn identity import alice.pub
```

## vault

Manage encrypted vaults.

### vault create

Create a new vault. The caller's identity becomes the Owner. Generates a random
256-bit master key and seals it to the creator's X25519 public key.

```bash
sigyn vault create myapp
```

Creates the vault directory with `vault.toml`, `members.cbor`, `policy.cbor`, default
environments (dev, staging, prod), and an audit log.

### vault list

List all vaults on this machine with their environments.

```bash
sigyn vault list
```

### vault open

Open (unlock) a vault for the current session.

```bash
sigyn vault open myapp
```

### vault delete

Delete a vault and all its data.

```bash
sigyn vault delete myapp
```

### vault info

Show vault metadata (UUID, owner fingerprint, environments, creation date).

```bash
sigyn vault info myapp
sigyn vault info                     # uses default vault
sigyn vault info myapp --json
```

## secret

Manage secrets within a vault environment.

### secret set

Set a secret value. Reads from stdin if value is omitted.

```bash
sigyn secret set DATABASE_URL 'postgres://localhost/mydb' --env dev
echo 'supersecret' | sigyn secret set API_KEY --env prod
```

| Flag | Description |
|---|---|
| `--env, -e <ENV>` | Target environment (default: dev) |

### secret get

Retrieve and decrypt a secret value.

```bash
sigyn secret get DATABASE_URL --env dev
sigyn secret get API_KEY --env prod --json
```

JSON output includes key, value, type, environment, and version.

### secret list

List all secrets in an environment. Values are hidden by default.

```bash
sigyn secret list --env dev
sigyn secret list --env dev --reveal
```

| Flag | Short | Description |
|---|---|---|
| `--env` | `-e` | Target environment (default: dev) |
| `--reveal` | `-r` | Show decrypted values instead of masked output |

### secret remove (alias: rm)

Delete a secret from an environment.

```bash
sigyn secret remove OLD_KEY --env dev
sigyn secret rm UNUSED_VAR --env staging
```

### secret generate

Generate a random secret and store it.

```bash
sigyn secret generate JWT_SECRET --env dev
sigyn secret generate API_TOKEN --env dev --length 64 --type hex
sigyn secret generate SESSION_ID --env dev --type uuid
```

| Flag | Short | Description |
|---|---|---|
| `--length` | `-l` | Length of generated value (default: 32) |
| `--type` | `-t` | Generation type: `password`, `uuid`, `hex`, `base64`, `alphanumeric` (default: password) |
| `--env` | `-e` | Target environment (default: dev) |

### secret history

Show the change history of a secret.

```bash
sigyn secret history DATABASE_URL --env dev
```

## env

Manage environments within a vault.

### env list

List all environments in a vault.

```bash
sigyn env list
sigyn env list --vault myapp
```

### env create

Create a new environment.

```bash
sigyn env create qa
sigyn env create canary --vault myapp
```

### env promote

Copy secrets from one environment to another. Reports promoted, overwritten, and
skipped keys.

```bash
sigyn env promote --from dev --to staging
sigyn env promote --from staging --to prod --keys DATABASE_URL,API_KEY
```

| Flag | Description |
|---|---|
| `--from <ENV>` | Source environment |
| `--to <ENV>` | Target environment |
| `--keys <K1,K2,...>` | Optional comma-separated list of keys to promote (default: all) |

## policy

Manage access policies, members, and RBAC rules.

### policy show

Display the vault policy: owner, all members with their roles, allowed environments,
secret patterns, and delegation chain.

```bash
sigyn policy show
sigyn policy show --vault myapp --json
```

### policy member-add

Add a member to the vault policy. The member's `delegated_by` is automatically set
to the caller's fingerprint.

```bash
sigyn policy member-add a1b2c3d4e5f6... --role contributor --envs dev,staging
sigyn policy member-add a1b2c3d4e5f6... --role readonly --envs '*' --patterns 'DB_*,API_*'
```

| Flag | Description |
|---|---|
| `--role <ROLE>` | Role to assign: `readonly`, `auditor`, `operator`, `contributor`, `manager`, `admin` (default: readonly) |
| `--envs <ENVS>` | Comma-separated allowed environments, or `*` for all (default: `*`) |
| `--patterns <PATS>` | Comma-separated secret key glob patterns (default: `*`) |

### policy member-remove

Remove a member from the vault policy.

```bash
sigyn policy member-remove a1b2c3d4e5f6...
```

### policy check

Test whether a specific access request would be allowed or denied.

```bash
sigyn policy check a1b2c3d4e5f6... read --env dev
sigyn policy check a1b2c3d4e5f6... write --env prod --key DATABASE_URL
```

| Flag | Description |
|---|---|
| `--env, -e <ENV>` | Environment to check (default: dev) |
| `--key, -k <KEY>` | Optional secret key to check |

Actions: `read`, `write`, `delete`, `manage-members`, `manage-policy`, `create-env`, `promote`.

## delegation (alias: member)

Manage the delegation tree and invitations.

### delegation tree

Display the delegation tree showing who invited whom.

```bash
sigyn delegation tree
sigyn member tree --vault myapp
```

Example output:

```
alice (a1b2c3d4...) [owner]
  bob (e5f6a7b8...) [admin]
    carol (c9d0e1f2...) [contributor]
  dave (a3b4c5d6...) [manager]
```

### delegation invite create

Create a signed invitation file for a new member. The invitation is an Ed25519-signed
JSON document that can be shared out-of-band (email, chat, etc.).

```bash
sigyn delegation invite create --role contributor --envs dev,staging
sigyn delegation invite create --role readonly --envs '*' --expires 7d
```

### delegation invite accept

Accept an invitation file and join a vault. Verifies the Ed25519 signature before
accepting.

```bash
sigyn delegation invite accept ./invitation-abc123.json
```

### delegation revoke

Revoke a member's access. The master key is always rotated on revoke.

```bash
sigyn delegation revoke a1b2c3d4e5f6...
sigyn delegation revoke a1b2c3d4e5f6... --cascade
```

With `--cascade`, performs BFS traversal of the delegation tree and revokes the target
plus everyone they transitively invited. See [Delegation](delegation.md) for details.

### delegation pending

List pending invitations.

```bash
sigyn delegation pending
```

## audit

View and verify the hash-chained audit trail.

### audit tail

Show the most recent audit entries.

```bash
sigyn audit tail
sigyn audit tail -n 50
sigyn audit tail --vault myapp --json
```

| Flag | Description |
|---|---|
| `-n <COUNT>` | Number of entries to show (default: 20) |

### audit query

Search the audit log with filters.

```bash
sigyn audit query --actor a1b2c3d4...
sigyn audit query --env prod
sigyn audit query --actor a1b2c3d4... --env dev
```

### audit verify

Verify the integrity of the hash chain. Reports the first broken entry if tampering
is detected.

```bash
sigyn audit verify
sigyn audit verify --vault myapp
```

### audit export

Export the full audit log to a file.

```bash
sigyn audit export --output audit.json --format json
sigyn audit export --output audit.csv --format csv
```

| Flag | Description |
|---|---|
| `--output <PATH>` | Output file path |
| `--format <FMT>` | Export format: `json` or `csv` (default: json) |

### audit witness

Countersign the latest audit entry with your Ed25519 key. Provides independent
verification that a second party observed the entry.

```bash
sigyn audit witness
sigyn audit witness --vault myapp
```

### audit anchor

Anchor the latest audit hash to an external system for additional tamper evidence.

```bash
sigyn audit anchor --target git
```

## sync

Synchronize vaults via git. All data is encrypted at rest; sync never needs the
master key.

### sync push

Push local vault changes to a remote repository.

```bash
sigyn sync push
sigyn sync push --remote origin --branch main
```

| Flag | Description |
|---|---|
| `--remote <NAME>` | Git remote name (default: origin) |
| `--branch <NAME>` | Branch name (default: main) |

### sync pull

Pull remote changes into the local vault.

```bash
sigyn sync pull
sigyn sync pull --remote origin --branch main
```

### sync status

Show sync status (clean, local changes, ahead/behind remote).

```bash
sigyn sync status
sigyn sync status --vault myapp
```

### sync resolve

Resolve a sync conflict for a specific key.

```bash
sigyn sync resolve DATABASE_URL --strategy local
sigyn sync resolve API_KEY --strategy remote
sigyn sync resolve CONFIG --strategy latest
```

| Flag | Description |
|---|---|
| `--strategy <S>` | Resolution strategy: `local`, `remote`, `latest` |

### sync peers

List known peers (LAN discovery via mDNS and remote).

```bash
sigyn sync peers
```

### sync configure

Configure sync settings for a vault.

```bash
sigyn sync configure --remote-url git@github.com:team/secrets.git
sigyn sync configure --auto-sync true
```

## fork

Manage vault forks for isolated workstreams.

### fork create

Create a fork of the current vault.

```bash
sigyn fork create feature-branch
sigyn fork create sandbox --mode unleashed
sigyn fork create sprint-3 --mode leashed --expires-days 30
```

| Flag | Description |
|---|---|
| `--mode <MODE>` | Fork mode: `leashed` (connected to parent) or `unleashed` (independent). Default: leashed |
| `--expires-days <N>` | Days until fork expires. 0 = no expiry. Default: 0 |

### fork list

List all forks for a vault.

```bash
sigyn fork list
```

### fork sync

Sync a leashed fork with its parent vault.

```bash
sigyn fork sync feature-branch
```

### fork approve

Approve pending changes from a fork back to the parent.

```bash
sigyn fork approve feature-branch
```

### fork expire

Manually expire a fork.

```bash
sigyn fork expire feature-branch
```

### fork status

Show the status of a specific fork.

```bash
sigyn fork status feature-branch
```

## project

Manage project-level configuration.

### project init

Generate a `.sigyn.toml` in the current directory. Interactively prompts to select
a vault and identity from those available on the machine.

```bash
sigyn project init                          # interactive
sigyn project init -v myapp -i alice        # non-interactive
sigyn project init --global                 # write to ~/.sigyn/project.toml instead
```

| Flag | Short | Description |
|---|---|---|
| `--vault` | `-v` | Vault name (skips prompt) |
| `--env` | `-e` | Environment name (default: dev) |
| `--identity` | `-i` | Identity name (skips prompt) |
| `--global` | | Write to `~/.sigyn/project.toml` instead of `./.sigyn.toml` |

## run

Run processes with injected secrets or export secrets in various formats.

The `exec` subcommand is the default -- you can omit it:

```bash
# These are equivalent:
sigyn run -- ./my-app
sigyn run exec -- ./my-app
```

### run (exec)

Execute a command with secrets injected as environment variables. Secrets are never
written to disk in plaintext.

```bash
sigyn run -e dev -- ./my-app
sigyn run --prod -- docker compose up
sigyn run -e dev -c -- node server.js
```

| Flag | Short | Description |
|---|---|---|
| `--env` | `-e` | Environment to load secrets from |
| `--clean` | `-c` | Do not inherit the parent process environment |
| `--prod` | | Shorthand for `--env prod` |
| `--staging` | | Shorthand for `--env staging` |

### Named commands

If a `.sigyn.toml` is present with a `[commands]` table, you can run named commands:

```toml
# .sigyn.toml
[commands]
dev = "npm run dev"
app = "./my-app"
```

```bash
sigyn run dev              # runs 'npm run dev' with secrets injected
sigyn run app --prod       # runs './my-app' with prod env secrets
```

### run export

Export secrets in a specified format to stdout.

```bash
sigyn run export --env dev --format dotenv > .env
sigyn run export --env dev --format json
sigyn run export --env prod --format k8s --name my-app-secrets
sigyn run export --env dev --format docker
sigyn run export --env dev --format shell
```

| Flag | Short | Description |
|---|---|---|
| `--env` | `-e` | Environment to export |
| `--format` | `-f` | Output format: `dotenv`, `json`, `shell`, `docker`, `k8s` (default: dotenv) |
| `--name` | | Resource name for k8s format (default: app-secrets) |

### run serve

Serve secrets over a Unix domain socket for local process consumption.

```bash
sigyn run serve --env dev
sigyn run serve --env dev --socket /tmp/my-app.sock
```

## rotate

Manage secret rotation and lifecycle.

### rotate key

Rotate a specific secret by generating a new random value.

```bash
sigyn rotate key DATABASE_PASSWORD --env prod
sigyn rotate key API_KEY --env dev
```

### rotate schedule

Show configured rotation schedules.

```bash
sigyn rotate schedule
```

### rotate due

List secrets that are due for rotation based on age.

```bash
sigyn rotate due --env dev
sigyn rotate due --env prod --max-age 30
```

| Flag | Description |
|---|---|
| `--max-age <DAYS>` | Maximum age in days before a secret is considered due (default: 90) |
| `--env, -e <ENV>` | Environment to check |

### rotate breach-mode

Activate breach mode: rotate all secrets across all environments and revoke all
delegated members. Requires confirmation unless `--force` is set.

```bash
sigyn rotate breach-mode
sigyn rotate breach-mode --force
```

### rotate dead-check

Find unused or stale secrets that may be candidates for removal.

```bash
sigyn rotate dead-check --env dev
sigyn rotate dead-check --env prod --max-age 365
```

| Flag | Description |
|---|---|
| `--max-age <DAYS>` | Maximum age in days (default: 180) |

## import

Import secrets from external files and cloud providers.

### import dotenv

Import key-value pairs from a `.env` file.

```bash
sigyn import dotenv .env --env dev
sigyn import dotenv /path/to/production.env --env prod
```

### import json

Import key-value pairs from a JSON file (expects a flat object with string values).

```bash
sigyn import json secrets.json --env dev
```

### import doppler

Import secrets from Doppler.

```bash
sigyn import doppler --project myapp --config dev --env dev
```

### import aws

Import a secret from AWS Secrets Manager.

```bash
sigyn import aws --secret-id myapp/db-credentials --env prod
sigyn import aws --secret-id arn:aws:secretsmanager:... --region us-east-1 --env prod
```

### import gcp

Import a secret from GCP Secret Manager.

```bash
sigyn import gcp --project my-gcp-project --secret db-password --env prod
sigyn import gcp --project my-gcp-project --secret api-key --version 3 --env prod
```

### import 1password (alias: op)

Import secrets from 1Password via the `op` CLI.

```bash
sigyn import 1password --vault "Dev Secrets" --item "API Keys" --env dev
sigyn import op --vault Production --item "Database Creds" --env prod
```

## recovery

Disaster recovery via the standalone `sigyn-recovery` binary.

### recovery split

Split an identity's private key into Shamir shards.

```bash
sigyn-recovery split --identity alice --threshold 3 --total 5
sigyn-recovery split --identity alice --threshold 2 --total 3 --output ./shards
```

### recovery restore

Reconstruct an identity from Shamir shards.

```bash
sigyn-recovery restore shard-a1b2c3d4-1.json shard-a1b2c3d4-2.json shard-a1b2c3d4-3.json
sigyn-recovery restore shard-*.json --output recovered_key.bin
```

### recovery print-shards

Print shard details for labeling paper backups.

```bash
sigyn-recovery print-shards shard-a1b2c3d4-*.json
```

### recovery snapshots

List available vault snapshots from git history.

```bash
sigyn-recovery snapshots --vault myapp
```

### recovery succession

Manage succession planning (dead-man trigger for vault ownership transfer).

```bash
sigyn-recovery succession show
sigyn-recovery succession set --successor b2c3d4e5f6... --dead-man-days 90
```

## Utility Commands

### tui

Launch the interactive TUI dashboard (built with ratatui + crossterm).

```bash
sigyn tui
sigyn tui --vault myapp --env dev
```

### doctor

Run health checks on the Sigyn installation.

```bash
sigyn doctor
```

### status

Show current configuration status (default identity, vault, environment).

```bash
sigyn status
sigyn status --json
```

### init

Initialize the default configuration file at `~/.sigyn/config.toml`.

```bash
sigyn init
sigyn init --identity alice --vault myapp
```

### completions

Generate shell completion scripts.

```bash
sigyn completions bash > ~/.local/share/bash-completion/completions/sigyn
sigyn completions zsh > ~/.zfunc/_sigyn
sigyn completions fish > ~/.config/fish/completions/sigyn.fish
sigyn completions powershell >> $PROFILE
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`.

## Related Documentation

- [Getting Started](getting-started.md) -- step-by-step tutorial
- [Architecture](architecture.md) -- project structure and design decisions
- [Security Model](security.md) -- cryptographic primitives and threat model
- [Delegation](delegation.md) -- invitation and revocation system
- [Sync](sync.md) -- synchronization and conflict resolution
