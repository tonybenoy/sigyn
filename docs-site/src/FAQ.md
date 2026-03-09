# Frequently Asked Questions

## General

### What is Sigyn?

Sigyn is a free, open-source, serverless secret manager for developers and teams. It encrypts your API keys, database credentials, and other secrets at rest, stores them locally, and syncs them between team members via git -- with no central server or SaaS dependency.

### How does Sigyn compare to Doppler, AWS Secrets Manager, or HashiCorp Vault?

Unlike hosted secret managers, Sigyn requires no server infrastructure and has no monthly cost. Your secrets live in your own git repositories, giving you full control over your data. Sigyn uses the same enterprise-grade cryptography (ChaCha20-Poly1305, X25519, Ed25519, Argon2id) but without vendor lock-in or third-party availability concerns.

| | Sigyn | Doppler | AWS Secrets Manager | HashiCorp Vault |
|---|---|---|---|---|
| Self-hosted | Yes (git) | No | No | Yes |
| Server required | No | Yes (SaaS) | Yes (AWS) | Yes |
| Cost | Free | Paid | Per-secret pricing | Free (OSS) / Paid |
| Encryption | E2E (client-side) | Server-side | Server-side | Server-side |
| Sync | Git | API | API | API |

### What platforms does Sigyn support?

Sigyn runs on macOS (Intel and Apple Silicon), Linux (x86_64 and ARM64), and Windows (x86_64). Install with a single command:

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.ps1 | iex
```

---

## Getting Started

### How do I set up Sigyn for an existing project?

Run `sigyn project init` in your project root, then import your existing `.env` file:

```bash
sigyn project init
sigyn import dotenv .env -e dev
```

This creates a `.sigyn.toml` with your vault and identity, then encrypts your secrets.

### What is the config file priority order?

Sigyn resolves settings in this order (highest to lowest):

1. CLI flags (`--vault`, `--env`, `--identity`)
2. `.sigyn.toml` in current or parent directory
3. `~/.sigyn/project.toml`
4. `~/.sigyn/config.toml`
5. Built-in defaults

### Is it safe to commit `.sigyn.toml` to my repository?

Yes. The `.sigyn.toml` project config only contains vault/environment/identity names and command aliases -- never secret values. It's designed to be committed and shared with your team.

### What are the naming rules for vaults, environments, and identities?

Names must be 1--64 characters, contain only `[a-zA-Z0-9-_]`, and cannot start with `.` or contain `..`.

---

## Secrets & Environments

### How do I inject secrets into my application?

Use the `sigyn run` command. Secrets are passed directly as environment variables to the child process without writing them to disk:

```bash
sigyn run -e dev -- ./my-app
sigyn run --prod -- docker compose up
```

### What export formats does `sigyn run export` support?

Five formats are available:

```bash
sigyn run export -e dev -f dotenv    # .env file (default)
sigyn run export -e dev -f json      # JSON object
sigyn run export -e dev -f shell     # Shell export statements
sigyn run export -e dev -f docker    # Docker --env-file format
sigyn run export -e dev -f k8s       # Kubernetes Secret YAML manifest
```

### Can I use `{{KEY}}` substitution in commands?

Yes, but only with the `--allow-inline-secrets` flag to prevent secrets from leaking into the process list:

```bash
sigyn run exec --allow-inline-secrets -- bash -c 'echo {{API_KEY}}'
```

Without the flag, `{{KEY}}` references are left as-is.

### Are secrets in different environments cryptographically isolated?

Yes. Each environment has its own independent 256-bit encryption key. Members only receive keys for environments they're authorized to access -- they physically cannot decrypt other environments, even with direct file access.

### How do I promote secrets across environments?

Use `sigyn env promote`. Multiple targets can be chained in a single command:

```bash
sigyn env promote --from dev --to staging
sigyn env promote --from dev --to staging,prod            # chained: dev → staging → prod
sigyn env promote --from staging --to prod --keys DB_URL  # specific keys only
```

### What secret key names are valid?

Keys must start with a letter or underscore (`[A-Za-z_]`), and contain only alphanumerics, underscores, dots, dashes, and slashes. Maximum 128 characters. Nested paths like `db/primary/host` are supported.

### Does Sigyn auto-sync after writing secrets?

If `auto_sync = true` in your `~/.sigyn/config.toml`, Sigyn automatically pushes after secret set, delete, edit, import, and environment promote operations.

---

## Team Collaboration

### How do I share secrets with my team?

The quickest workflow:

```bash
# You: create vault with sync, invite teammate
sigyn vault create myapp --remote-url git@github.com:team/secrets.git
sigyn delegation invite --pubkey <bob-fingerprint> --role contributor --envs dev,staging --save-to-vault
sigyn sync push

# Bob: clone and accept in one step
sigyn vault clone git@github.com:team/secrets.git --invitation <uuid-or-path>
```

### How do I clone a vault that someone shared with me?

Use `sigyn vault clone` with the git URL. Optionally accept the invitation in the same command:

```bash
# Single command (clone + accept invitation)
sigyn vault clone git@github.com:team/secrets.git --invitation ./invitation.json

# Or step by step
sigyn vault clone git@github.com:team/secrets.git
sigyn delegation accept ./invitation.json
```

The vault name is derived from the repository URL automatically, or override with `--name`.

### What does `--save-to-vault` do on `delegation invite`?

It saves a copy of the invitation to the vault's `invitations/` directory. After you `sigyn sync push`, the invitee can clone the repo and accept using the UUID -- no manual file transfer needed.

### What does "inviter identity not found locally" mean?

When accepting an invitation, Sigyn verifies the Ed25519 signature using the inviter's public key. If their identity file isn't on your machine, verification fails. Import the inviter's identity first, then re-accept.

### What happens if two people edit the same secret at the same time?

Sigyn uses vector clocks and CRDTs (Conflict-free Replicated Data Types) to resolve conflicts deterministically. By default, Last-Write-Wins (LWW) is used. You can manually resolve conflicts with `sigyn sync resolve`.

---

## Security

### Is my passphrase stored anywhere?

No. Your passphrase is processed through Argon2id to derive a key that decrypts your private keys. The passphrase itself is never written to disk or stored in memory beyond the current operation.

### What happens if I lose my passphrase?

If you lose your passphrase and haven't set up Shamir recovery shards, your secrets are permanently inaccessible. Set up recovery shards immediately after creating an identity:

```bash
sigyn-recovery split --identity alice --threshold 3 --total 5
```

Any 3 of the 5 shards can reconstruct the key; fewer than 3 reveal nothing. Distribute shards to trusted parties in different locations.

### Are my secrets encrypted in git?

Yes. Every secret is encrypted with ChaCha20-Poly1305 before being committed to git. Even with full access to the git repository, secrets cannot be read without an authorized private key.

### What dangerous environment variables does `sigyn run` block?

`sigyn run` prevents secrets from overriding critical system variables to prevent hijacking:

- **Execution:** `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`
- **Sensitive:** `SIGYN_HOME`, `SIGYN_PASSPHRASE`

If a secret conflicts, it's skipped with a warning. Rename the secret or use `sigyn run serve` for socket-based injection.

### Is clipboard data cleared automatically?

Yes. When you copy a secret with `sigyn secret get --copy`, the clipboard is automatically cleared after 30 seconds.

### What is TOFU (Trust On First Use)?

On first vault access, Sigyn pins the vault ID and owner fingerprint locally. On subsequent access, it verifies they match. If the owner changed unexpectedly (possible copy-and-rehost attack), the unlock is blocked. Use `sigyn vault trust <name> --accept-new-owner` if the change is legitimate.

### What does the "rollback detected" warning mean?

The remote git history doesn't descend from your last sync checkpoint. Someone may have force-pushed to restore revoked access. Sigyn rejects this by default. Use `sigyn sync pull --force` only if you trust the change.

### What is split-repo audit?

With `sigyn vault create <name> --split-audit`, vault data and audit data live in separate git repos. This lets auditors have read access to audit logs without accessing the vault's encrypted secrets.

---

## CI/CD

### Can I use Sigyn in CI/CD?

Yes. Use the official GitHub Action or run `sigyn run export` directly:

```yaml
- uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-repo: git@github.com:team/secrets.git
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-name: myapp
    env: prod
```

### What is SIGYN_CI_BUNDLE?

A base64-encoded bundle containing the CI identity file, device key, and identity fingerprint. Generate it with:

```bash
sigyn ci setup <identity-name>
```

Store the output as a CI secret (e.g., GitHub Secret).

---

## Forks

### What is a fork?

A fork creates a copy of a vault for branching workflows -- like feature branches, org splits, or experiment isolation.

### What's the difference between leashed and unleashed forks?

- **Leashed fork:** Stays connected to the parent vault. The parent admin can audit, revoke, or expire the fork. Secrets can sync back with approval. Good for feature branches.
- **Unleashed fork:** Fully independent with a new master key. No upstream access or connection. Good for permanent org splits.

### Can unleashed forks sync back to the parent?

No. Unleashed forks are cryptographically independent. Only leashed forks maintain a connection for syncing changes back.

---

## Recovery

### How does Shamir secret sharing work in Sigyn?

Shamir's scheme splits your identity's encrypted private key into N shards, any K of which can reconstruct it. For example, 3-of-5 means you distribute 5 shards and any 3 can recover the key, but 2 or fewer reveal nothing.

```bash
# Create shards
sigyn-recovery split --identity alice --threshold 3 --total 5

# Restore from shards
sigyn-recovery restore --shards shard1.json,shard2.json,shard3.json
```

### Where should I store recovery shards?

Distribute shards to trusted parties in different physical locations: printed paper in a safe, USB drives with different colleagues, password manager vaults. Never store all shards in one place.
