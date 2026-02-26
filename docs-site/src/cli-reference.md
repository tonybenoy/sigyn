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
| `--verbose` | | Show detailed config resolution and debug output |
| `--no-project-config` | | Skip loading `.sigyn.toml` project config |

**Resolution priority:** CLI flags > `~/.sigyn/context.toml` > `.sigyn.toml` (project dir) > `~/.sigyn/project.toml` > `~/.sigyn/config.toml` > defaults.

### Command Aliases

Most commands have short aliases for quick typing:

| Command | Alias |
|---|---|
| `identity` | `id` |
| `vault` | `v` |
| `secret` | `s` |
| `env` | `e` |
| `policy` | `p` |
| `sync` | `sy` |
| `audit` | `a` |
| `fork` | `f` |
| `run` | `r` |
| `rotate` | `rot` |
| `import` | `imp` |
| `delegation` | `member` |
| `notification` | `notif` |
| `context` | `ctx` |

### Environment Prefix Matching

Environment names support unambiguous prefix matching. If your vault has `dev`, `staging`, and `prod` environments:

```bash
sigyn secret get API_KEY -e d    # resolves to 'dev'
sigyn secret get API_KEY -e p    # resolves to 'prod'
sigyn secret get API_KEY -e s    # resolves to 'staging'
sigyn secret get API_KEY -e st   # also resolves to 'staging'
```

Ambiguous prefixes produce an error listing the matches.

### Environment Variables

| Variable | Description |
|---|---|
| `SIGYN_HOME` | Override the Sigyn home directory (default: `~/.sigyn`) |
| `SIGYN_NON_INTERACTIVE` | Disable all interactive prompts (equivalent to piping to a non-TTY) |
| `CI` | When set, disables interactive prompts (auto-detected in most CI systems) |

## get (shortcut)

Get a secret value. This is a shortcut for `sigyn secret get`.

```bash
sigyn get DATABASE_URL -e dev
sigyn get API_KEY --copy           # copy to clipboard
sigyn get API_KEY -e prod --json
```

| Flag | Short | Description |
|---|---|---|
| `--copy` | `-c` | Copy value to clipboard instead of printing (auto-clears after 30s) |

Uses the global `--env` / `-e` flag for environment selection.

## set (shortcut)

Set a secret value. This is a shortcut for `sigyn secret set`.

```bash
sigyn set DATABASE_URL 'postgres://localhost/mydb' -e dev
echo 'supersecret' | sigyn set API_KEY -e prod
```

Uses the global `--env` / `-e` flag for environment selection.

## ls (quick list)

Quick listing of secrets, vaults, or environments.

```bash
sigyn ls                    # list secrets in default env
sigyn ls prod               # list secrets in 'prod' env (prefix matching)
sigyn ls --vaults           # list all vaults
sigyn ls --envs             # list all environments
sigyn ls dev --reveal       # list secrets with values shown
```

| Flag | Short | Description |
|---|---|---|
| `--vaults` | | List vaults instead of secrets |
| `--envs` | | List environments instead of secrets |
| `--reveal` | `-r` | Show decrypted values |

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

### identity change-passphrase

Change the passphrase for an existing identity. Verifies the old passphrase, then
re-wraps the keys with a fresh salt. Clears the agent cache after success.

```bash
sigyn identity change-passphrase alice
sigyn identity change-passphrase          # uses default identity
```

Prompts for current passphrase, then new passphrase with confirmation (minimum 8 characters).

### identity delete

Delete an identity from this machine. Requires passphrase to prove ownership.
Before deleting, checks whether the identity is a member of any local vaults.

```bash
sigyn identity delete alice
sigyn identity delete a1b2c3d4... --force
```

| Flag | Description |
|---|---|
| `--force` | Skip vault membership check and delete anyway |

If the identity is a member of vaults, the command errors with the vault list unless `--force` is used. Interactive mode shows a confirmation prompt.

### identity rotate-keys

Create a new keypair with a new fingerprint, replacing the old identity. The old identity
is deleted only after the new one is successfully created.

```bash
sigyn identity rotate-keys
sigyn identity rotate-keys alice
```

**Warning:** This creates a new fingerprint. You must be re-invited to all vaults after rotation. There is no automatic migration.

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

## vault (alias: v)

Manage encrypted vaults.

### vault create

Create one or more vaults. The caller's identity becomes the Owner. Generates a random
256-bit master key and seals it to the creator's X25519 public key.

```bash
sigyn vault create myapp
sigyn vault create frontend backend worker --org acme -i alice
```

Accepts multiple names for batch creation. All vaults share the same `--org` and flags.
Creates the vault directory with `vault.toml`, `members.cbor`, `policy.cbor`, default
environments (dev, staging, prod), and an audit log. After creation, Sigyn prints
suggested next steps and offers to create a `.sigyn.toml` project config in the
current directory (interactive terminals only, single vault only).

**Naming rules:** Vault and environment names must be 1-64 characters, contain only `[a-zA-Z0-9-_]`, and cannot start with `.` or contain `..`.

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

Delete a vault and all its data. Owner-only. Writes an audit entry and attempts a
sync push before destroying the directory. Removes the vault from the pinned vaults store.

```bash
sigyn vault delete myapp
sigyn vault delete myapp --force
```

| Flag | Description |
|---|---|
| `--force` | Skip member check and confirmation in non-interactive mode |

In interactive mode, you must type the vault name to confirm (not just yes/no). If other
members exist, the command errors unless `--force` is used.

### vault info

Show vault metadata (UUID, owner fingerprint, environments, creation date).

```bash
sigyn vault info myapp
sigyn vault info                     # uses default vault
sigyn vault info myapp --json
```

### vault transfer

Transfer ownership of a vault to another member. This is phase 1 of a two-phase transfer.
The new owner must already be a member of the vault.

```bash
sigyn vault transfer myapp --to a1b2c3d4e5f6...
sigyn vault transfer myapp --to a1b2c3d4e5f6... --downgrade-to admin
sigyn vault transfer myapp --to a1b2c3d4e5f6... --downgrade-to remove
```

| Flag | Description |
|---|---|
| `--to <FP>` | Fingerprint of the new owner (must be an existing member) |
| `--downgrade-to <ROLE>` | Role for old owner after transfer (default: `admin`). Use `remove` to leave the vault. |

Creates a signed `pending_transfer.cbor` recording the intended transfer. The vault's
manifest and policy are **not** changed until the new owner accepts — the old owner
retains full control in the interim. Transfers expire after 7 days.

### vault accept-transfer

Accept a pending ownership transfer (phase 2). Verifies the old owner's signature,
checks the transfer has not expired, then atomically updates the manifest owner,
adjusts the policy (downgrading/removing the old owner), re-signs the header and
policy with the new owner's signing key, and updates the TOFU pin.

```bash
sigyn vault accept-transfer myapp
```

If the transfer has expired, the pending file is removed and the old owner must
initiate a new transfer.

### vault export

Export a vault as an encrypted tar.gz archive. All data on disk is already encrypted, so
the archive contains no plaintext secrets. Requires Admin+ access.

```bash
sigyn vault export myapp -o backup.tar.gz
sigyn vault export myapp --output /backups/myapp-2025.tar.gz
```

| Flag | Short | Description |
|---|---|---|
| `--output` | `-o` | Output file path for the tar.gz archive |
| `--force` | | Overwrite the output file if it already exists |

## secret (alias: s)

Manage secrets within a vault environment.

### secret set

Set one or more secrets. Supports `KEY VALUE`, `KEY=VALUE`, or multiple `KEY=VALUE` pairs.
Reads from stdin if a single key is given with no value.

```bash
sigyn secret set DATABASE_URL 'postgres://localhost/mydb' --env dev
sigyn secret set DATABASE_URL='postgres://localhost/mydb' --env dev
sigyn secret set DB_URL=postgres://localhost API_KEY=sk-123 REDIS=redis://localhost -e dev
echo 'supersecret' | sigyn secret set API_KEY --env prod
```

| Flag | Description |
|---|---|
| `--env, -e <ENV>` | Target environment (default: dev) |

### secret import (alias: imp)

Import secrets from a `.env` file.

```bash
sigyn secret import .env --env dev
sigyn secret import .env.production --env prod --force
cat secrets.env | sigyn secret import - --env dev
```

| Flag | Description |
|---|---|
| `--env, -e <ENV>` | Target environment (default: dev) |
| `--force` | Overwrite existing secrets without prompting |

### secret get

Retrieve and decrypt a secret value.

```bash
sigyn secret get DATABASE_URL --env dev
sigyn secret get API_KEY --env prod --json
sigyn secret get API_KEY --env dev --copy    # copy to clipboard
```

| Flag | Short | Description |
|---|---|---|
| `--env` | `-e` | Target environment (default: dev) |
| `--copy` | `-c` | Copy value to clipboard instead of printing |

JSON output includes key, value, type, environment, and version. With `--copy`, JSON output includes `"copied": true` instead of the value.

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

Delete one or more secrets from an environment.

```bash
sigyn secret remove OLD_KEY --env dev
sigyn secret rm UNUSED_VAR --env staging
sigyn secret remove OLD_KEY1 OLD_KEY2 OLD_KEY3 -e dev
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

### secret edit

Open all secrets in an environment in `$EDITOR` for batch editing. On save, shows
a diff of changes (added, modified, removed keys) and asks for confirmation.

```bash
sigyn secret edit --env dev
EDITOR=nano sigyn secret edit --env staging
```

| Flag | Short | Description |
|---|---|---|
| `--env` | `-e` | Target environment (default: dev) |

### secret search

Search for secrets matching a glob pattern across all environments in a vault.

```bash
sigyn secret search 'DB_*'
sigyn secret search 'API_*' --reveal
sigyn secret search '*_URL' --json
```

| Flag | Short | Description |
|---|---|---|
| `--reveal` | `-r` | Show decrypted values (default: masked) |

Supports `*` (match any) and `?` (match single character) wildcards.

### secret history

Show the change history of a secret.

```bash
sigyn secret history DATABASE_URL --env dev
```

### secret copy

Copy secrets between vaults (or between environments in different vaults). Supports glob
patterns for key matching. Each vault is unlocked separately, and both sides are audited.

```bash
sigyn secret copy DATABASE_URL --from-vault app1 --to-vault app2
sigyn secret copy 'DB_*' 'API_*' --from-vault src --to-vault dst --from-env prod --to-env staging
```

| Flag | Description |
|---|---|
| `--from-vault <NAME>` | Source vault name |
| `--to-vault <NAME>` | Destination vault name |
| `--from-env <ENV>` | Source environment (default: `dev`) |
| `--to-env <ENV>` | Destination environment (default: `dev`) |

Secrets are decrypted from the source vault and re-encrypted with the destination vault's
key. Requires Read access on source and Write access on destination. Audit entries are
written on both sides (SecretRead on source, SecretsCopied on destination).

## env (alias: e)

Manage environments within a vault.

### env list

List all environments in a vault.

```bash
sigyn env list
sigyn env list --vault myapp
```

### env create

Create one or more environments.

```bash
sigyn env create qa
sigyn env create staging canary prod --vault myapp
```

### env diff

Compare secrets between two environments. Shows added, removed, and changed keys.

```bash
sigyn env diff dev staging
sigyn env diff dev prod --reveal
sigyn env diff staging prod --json
```

| Flag | Description |
|---|---|
| `--reveal` | Show actual values in the diff (default: masked markers) |

### env clone

Clone all secrets from one environment to a new environment.

```bash
sigyn env clone dev qa
sigyn env clone staging canary
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

### env delete

Delete an environment and all its secrets. Requires Admin+ access. Cannot delete the
last environment in a vault.

```bash
sigyn env delete qa
sigyn env delete canary --force
```

| Flag | Description |
|---|---|
| `--force` | Skip confirmation prompt (required in non-interactive mode) |

Removes the environment file, updates the manifest, and cleans up the header's env_slots.
The deletion is audited.

## policy (alias: p)

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

### policy history

Show policy-related events from the audit log. Filters for member invitations, revocations,
policy changes, ownership transfers, and environment creation/deletion.

```bash
sigyn policy history
sigyn policy history -n 100
sigyn policy history --json
```

| Flag | Short | Description |
|---|---|---|
| `-n` | | Number of entries to show (default: 50) |

## mfa

Manage TOTP-based multi-factor authentication for identities.

### mfa setup

Enroll TOTP-based MFA for an identity. Generates a TOTP secret, displays the
`otpauth://` URI for your authenticator app, then verifies with a code. On success,
generates 8 single-use backup codes.

```bash
sigyn mfa setup -i alice
```

| Flag | Description |
|---|---|
| `--identity, -i <NAME>` | Identity to enroll (uses default if omitted) |
| `--json` | Output URI, secret, and backup codes as JSON |

### mfa disable

Disable MFA for an identity. Requires a valid TOTP code or backup code to confirm.

```bash
sigyn mfa disable -i alice
```

### mfa status

Show MFA enrollment status, including whether a session is active and how many
backup codes remain.

```bash
sigyn mfa status -i alice
```

### mfa backup

Generate a new set of 8 backup codes, invalidating any previous codes. Requires a
valid TOTP code to confirm.

```bash
sigyn mfa backup -i alice
```

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
accepting. After acceptance, Sigyn prints next steps (sync pull, test access) and
offers to create a `.sigyn.toml` for the vault.

```bash
sigyn delegation invite accept ./invitation-abc123.json
```

### delegation revoke

Revoke one or more members' access. Environment keys are rotated on revoke.

```bash
sigyn delegation revoke a1b2c3d4e5f6...
sigyn delegation revoke a1b2c3d4 b5c6d7e8 f9a0b1c2 --cascade
```

With `--cascade`, performs BFS traversal of the delegation tree and revokes the target
plus everyone they transitively invited. See [Delegation](delegation.md) for details.

### delegation grant-env

Grant one or more members access to an additional environment.

```bash
sigyn delegation grant-env a1b2c3d4 --env prod
sigyn delegation grant-env a1b2c3d4 b5c6d7e8 --env staging
```

### delegation revoke-env

Revoke one or more members' access to a specific environment. The environment key is rotated.

```bash
sigyn delegation revoke-env a1b2c3d4 --env prod
sigyn delegation revoke-env a1b2c3d4 b5c6d7e8 --env staging
```

### delegation pending

List pending invitations.

```bash
sigyn delegation pending
```

### delegation bulk-invite

Invite multiple members at once from a JSON file. All entries are validated before any
mutations are applied (all-or-nothing validation). Header and policy are saved once at
the end.

```bash
sigyn delegation bulk-invite --file members.json
sigyn delegation bulk-invite --file members.json --force
```

| Flag | Description |
|---|---|
| `--file <PATH>` | Path to JSON file with member definitions |
| `--force` | Skip confirmation prompt |

**File format** (JSON array):
```json
[
  {"fingerprint": "a1b2c3d4e5f6...", "role": "contributor", "envs": "dev,staging"},
  {"fingerprint": "f7e8d9c0b1a2...", "role": "readonly", "envs": "*"}
]
```

Each entry supports `fingerprint` (required), `role` (default: readonly), and `envs` (default: `*`).

### delegation bulk-revoke

Revoke multiple members at once from a JSON file. Delegates to the standard revoke logic,
including environment key rotation and optional cascade.

```bash
sigyn delegation bulk-revoke --file revoke-list.json
sigyn delegation bulk-revoke --file revoke-list.json --cascade --force
```

| Flag | Description |
|---|---|
| `--file <PATH>` | Path to JSON file with fingerprint list |
| `--cascade` | Also revoke all members they transitively invited |
| `--force` | Skip confirmation prompt |

**File format** (JSON array of fingerprint strings):
```json
["a1b2c3d4e5f6...", "f7e8d9c0b1a2..."]
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

Anchor the audit trail to a git commit for tamper-evidence.

```bash
sigyn audit anchor -v myapp
```

## sync (alias: sy)

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

### sync configure

Configure sync settings for a vault.

```bash
sigyn sync configure --remote-url git@github.com:team/secrets.git
sigyn sync configure --auto-sync true
```

## fork (alias: f)

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
a vault and identity from those available on the machine. Sigyn auto-detects the
project type from `package.json`, `Cargo.toml`, `pyproject.toml`, or `go.mod` and
pre-selects a matching vault if one exists.

```bash
sigyn project init                          # interactive (with auto-detection)
sigyn project init -v myapp -i alice        # non-interactive
sigyn project init --global                 # write to ~/.sigyn/project.toml instead
```

| Flag | Short | Description |
|---|---|---|
| `--vault` | `-v` | Vault name (skips prompt) |
| `--env` | `-e` | Environment name (default: dev) |
| `--identity` | `-i` | Identity name (skips prompt) |
| `--global` | | Write to `~/.sigyn/project.toml` instead of `./.sigyn.toml` |

## context (alias: ctx)

Manage a persistent context that sets default vault and environment. Stored at
`~/.sigyn/context.toml`. Context sits between CLI flags and `.sigyn.toml` in the
resolution chain.

### context set

Set the active context.

```bash
sigyn context set myapp          # set vault only
sigyn context set myapp prod     # set vault and env
sigyn ctx set myapp dev          # using alias
```

### context show

Show the current context.

```bash
sigyn context show
sigyn ctx show --json
```

### context clear

Clear the current context.

```bash
sigyn context clear
```

## run (alias: r)

Run processes with injected secrets or export secrets in various formats.

The `exec` subcommand is the default -- you can omit it:

```bash
# These are equivalent:
sigyn run -- ./my-app
sigyn run exec -- ./my-app
```

If no vault is configured (no `--vault`, no `.sigyn.toml`, no default), Sigyn will
detect the project type and offer to create a `.sigyn.toml` interactively. In
non-interactive environments (CI, piped output), it prints an actionable error instead.

Use `--dry-run` to preview what would happen without executing:

```bash
sigyn run --dry-run -e prod -- ./my-app
# [dry-run] Vault: 'myapp', env: 'prod', secrets: 12
# [dry-run] Command: ./my-app
# [dry-run] Clean env: no (inheriting parent)
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

### Inline Secret Refs

You can reference secrets directly in command arguments using `{{KEY}}` syntax.
The values are substituted before the command is executed:

```bash
sigyn run -e prod -- curl -H "Authorization: Bearer {{API_KEY}}" https://api.example.com
sigyn run -e dev -- psql "{{DATABASE_URL}}"
```

Unresolved refs (keys not found in the environment) are left as-is.

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

## watch

Watch for secret changes and automatically restart a command. Polls the encrypted
environment file for modifications and restarts the child process when changes are
detected.

```bash
sigyn watch -- npm run dev
sigyn watch -e staging --interval 5 -- ./my-app
sigyn watch --clean -- node server.js
```

| Flag | Short | Description |
|---|---|---|
| `--interval <SECS>` | | Poll interval in seconds (default: 2) |
| `--clean` | `-c` | Don't inherit the parent process environment |

Uses the global `--env` / `-e` flag for environment selection. If the child process
exits on its own, `watch` exits with the same code (does not restart).

## rotate (alias: rot)

Manage secret rotation and lifecycle.

### rotate key

Rotate a specific secret by generating a new random value.

```bash
sigyn rotate key DATABASE_PASSWORD --env prod
sigyn rotate key API_KEY --env dev
```

### rotate schedule list

List all rotation schedules.

```bash
sigyn rotate schedule list -v myapp
```

### rotate schedule set

Set a rotation schedule for a key.

```bash
sigyn rotate schedule set -v myapp --key DB_PASSWORD --cron "0 0 * * MON" --grace-hours 48
```

Options:
- `--key` — Secret key name
- `--cron` — Cron expression for schedule
- `--grace-hours` — Grace period in hours (default: 24)
- `--hooks` — Post-rotation hooks (comma-separated)

### rotate schedule remove

Remove a rotation schedule.

```bash
sigyn rotate schedule remove -v myapp --key DB_PASSWORD
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

## import (alias: imp)

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

## org

Manage hierarchical organizations. See [Organizations](organizations.md) for the full
design document.

### org create

Create a root organization. The caller becomes the owner.

```bash
sigyn org create acme
```

Creates `~/.sigyn/orgs/acme/` with `node.toml`, `members.cbor`, and `policy.cbor`.

### org node create

Add a child node to an existing org path.

```bash
sigyn org node create platform --parent acme --type division
sigyn org node create web --parent acme/platform --type team
```

| Flag | Description |
|---|---|
| `--parent <PATH>` | Parent org path (e.g., `acme` or `acme/platform`) |
| `--type <TYPE>` | Node type string (default: `team`) |

### org node remove

Remove an empty node (no children, no linked vaults).

```bash
sigyn org node remove acme/platform/web
```

### org tree

Display the hierarchy tree.

```bash
sigyn org tree
sigyn org tree --org acme
```

### org info

Show node metadata (UUID, type, owner, children, linked vaults, git remote).

```bash
sigyn org info acme/platform/web
```

### org policy show

Display the RBAC policy at a hierarchy node.

```bash
sigyn org policy show --path acme
```

### org policy member-add

Add a member at a hierarchy level. Permissions cascade to child nodes via inheritance.

```bash
sigyn org policy member-add <fingerprint> --role admin --path acme
```

| Flag | Description |
|---|---|
| `--role <ROLE>` | Role to assign: `readonly`, `auditor`, `operator`, `contributor`, `manager`, `admin`, `owner` |
| `--path <PATH>` | Org path where the membership applies |

### org policy member-remove

Remove a member from a hierarchy level.

```bash
sigyn org policy member-remove <fingerprint> --path acme
```

### org policy effective

Show the merged effective permissions for a member by walking the chain from the
target node to the root org.

```bash
sigyn org policy effective <fingerprint> --path acme/platform/web
```

### org sync configure

Set the git remote for a hierarchy node. Child nodes without an explicit remote
inherit from the nearest ancestor.

```bash
sigyn org sync configure --path acme --remote-url git@github.com:acme/secrets.git
sigyn org sync configure --path acme/platform/web --remote-url git@github.com:acme/web.git --branch develop
```

| Flag | Description |
|---|---|
| `--path <PATH>` | Org path to configure |
| `--remote-url <URL>` | Git remote URL |
| `--branch <NAME>` | Branch name (default: `main`) |

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

## agent

Manage the passphrase agent — an ssh-agent style daemon that caches decrypted keys in
memory, eliminating repeated passphrase prompts when running multiple commands.

### agent start

Start the agent daemon in the background.

```bash
eval $(sigyn agent start)
eval $(sigyn agent start --timeout 60)   # 60-minute cache
```

Prints a shell-eval-able export statement for `SIGYN_AGENT_SOCK`. The agent forks to
background and listens on a Unix socket with owner-only permissions (0600).

| Flag | Description |
|---|---|
| `--timeout <MINUTES>` | Key cache timeout (default: 30 minutes) |

### agent stop

Stop the agent daemon and zeroize all cached keys.

```bash
sigyn agent stop
```

### agent lock

Clear all cached keys but keep the daemon running.

```bash
sigyn agent lock
```

### agent status

Show whether the agent is running and how many keys are cached.

```bash
sigyn agent status
```

## Utility Commands

### tui

Launch the interactive TUI dashboard (built with ratatui + crossterm).

```bash
sigyn tui
sigyn tui --vault myapp --env dev
```

### doctor

Run health checks on the Sigyn installation. Checks include: home directory,
identities, vaults, config file, `.sigyn.toml` in the current directory tree,
default vault accessibility, git availability, pending invitations, and project
type detection.

```bash
sigyn doctor
```

### onboard

Guided first-run setup wizard. Walks through identity creation, vault creation,
`.env` file import, and `.sigyn.toml` setup. In non-interactive mode, prints a
checklist of what's missing.

```bash
sigyn onboard
sigyn onboard --json   # report setup status as JSON
```

### status

Show current configuration status including identity, vault, environments,
sync status, rotation schedules, and pending invitations.

```bash
sigyn status
sigyn status --json
```

### init

Initialize the default configuration file at `~/.sigyn/config.toml`. In interactive
mode, offers to create an identity and vault if none exist, then runs `doctor` checks.

```bash
sigyn init
sigyn init --identity alice --vault myapp
```

### notification configure

Interactively configure a webhook for receiving notifications about vault events.
Webhook URLs must use HTTPS (HTTP is only allowed for localhost). If a shared secret
is provided, requests include an `X-Sigyn-Signature` HMAC header for verification.

```bash
sigyn notification configure
```

### notification test

Send a test notification to all configured webhooks.

```bash
sigyn notification test
sigyn notification test --json
```

### notification list

List all configured webhook endpoints and their event filters.

```bash
sigyn notification list
sigyn notification list --json
```

### update

Self-update to the latest release. Downloads the appropriate binary for the current
platform and verifies the SHA-256 checksum before replacing the running binary.
The update will abort if the checksum file cannot be downloaded or verification fails.

**Security hardening:** HTTP requests have connect (10s) and total (120s) timeouts.
Archives exceeding 100 MiB are rejected. Tar entries with path traversal (`..`) are
blocked. Temp files use random names to prevent symlink attacks.

```bash
sigyn update
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
- [Organizations](organizations.md) -- hierarchical org structure and inherited RBAC
- [Delegation](delegation.md) -- invitation and revocation system
- [Sync](sync.md) -- synchronization and conflict resolution
