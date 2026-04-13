<p align="center">
  <img src="assets/logo.png" alt="Sigyn" width="200">
</p>

<h1 align="center">Sigyn</h1>

<p align="center"><strong>Serverless, encrypted, peer-to-peer secret management.</strong></p>

[![CI](https://github.com/tonybenoy/sigyn/actions/workflows/release.yml/badge.svg)](https://github.com/tonybenoy/sigyn/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-sigyn.org-blue)](https://sigyn.org)

Sigyn is a CLI secret manager that keeps every secret encrypted at rest,
syncs through plain Git, and never requires a central server. Think of it
as Doppler -- but fully serverless and peer-to-peer.

## Why "Sigyn"?

In Norse mythology, Sigyn is the goddess of fidelity and devotion -- she
faithfully holds a bowl over her bound husband Loki to shield him from
venom. Sigyn the tool does the same for your secrets: it stands guard over
your sensitive data, shielding it from exposure with steadfast encryption
and access control. Loyalty, protection, and quiet reliability -- that is
what Sigyn is about.

---

## Feature highlights

- **Encryption** -- ChaCha20-Poly1305 authenticated encryption, sealed with X25519 envelope encryption, Argon2id key derivation.
- **Git-native sync** -- secrets live in a Git repository; no proprietary server or SaaS dependency.
- **CRDT conflict resolution** -- vector clocks and LWW-Map CRDTs merge concurrent edits deterministically.
- **Role-based access control** -- seven-level hierarchy: ReadOnly, Auditor, Operator, Contributor, Manager, Admin, Owner.
- **Delegation trees** -- delegate permissions to peers with automatic cascade revocation.
- **Per-environment secrets** -- first-class support for dev, staging, production, and custom environments with cryptographic key isolation (each environment has its own independent encryption key).
- **Per-key ACLs** -- granular constraints including time windows, expiry, and MFA enforcement.
- **TOTP-based MFA** -- optional multi-factor authentication per identity with session-based grace periods and backup codes.
- **Signed audit trail** -- hash-chained, Ed25519-signed log of every secret operation.
- **Disaster recovery** -- Shamir secret sharing splits the master key into K-of-N shards.
- **Fork system** -- leashed and unleashed forks for team branches and experimentation.
- **Rotation scheduling** -- cron-based automatic rotation with breach mode for emergency re-key.
- **Import/export** -- bring secrets in from Doppler, AWS Secrets Manager, GCP Secret Manager, 1Password, or `.env` files; export to dotenv, JSON, Kubernetes secrets, Docker env, or shell eval.
- **Project config** -- `.sigyn.toml` for per-project vault, environment, identity defaults, and named run commands.
- **Process injection** -- `sigyn run -- cmd` injects secrets as environment variables without writing them to disk.
- **Unix socket server** -- programmatic access for scripts and CI pipelines.
- **Interactive TUI** -- ratatui-powered dashboard for browsing and managing secrets.
- **Hierarchical organizations** -- nested org/division/team hierarchy with inherited RBAC (highest role wins), per-level encryption, cascading member management, and configurable git remotes at any level.
- **Guided onboarding** -- `sigyn onboard` walks through identity, vault, import, and project setup.
- **Batch editing** -- `sigyn secret edit` opens secrets in `$EDITOR` for bulk changes.
- **Cross-env search** -- `sigyn secret search 'DB_*'` finds secrets across all environments.
- **Env diff & clone** -- compare or duplicate environments in one command.
- **Auto-sync** -- automatically push changes after writes when `auto_sync` is enabled.
- **Webhook notifications** -- get notified on secret changes, rotations, and revocations.
- **Self-update** -- `sigyn update` downloads and installs the latest release with checksum verification.
- **CI/CD integration** -- official GitHub Action plus GitLab CI and generic pipeline support with CI identity bundles.
- **Passphrase agent** -- ssh-agent-like daemon caches your passphrase for a session.
- **AI-agent safe** -- secrets never leak to coding agents (Claude Code, Cursor, Copilot). Process injection and socket-based serving keep credentials out of your shell environment where AI tools can see them.
- **Web GUI** -- browser-based dashboard for visual secret management (`sigyn web`), with the same encryption and policy enforcement as the CLI.
- **Watch mode** -- `sigyn watch` auto-restarts your app when secrets change.
- **Context switching** -- `sigyn context` sets persistent vault/env/identity defaults.
- **Shell completions** -- bash, zsh, fish, and PowerShell.

---

## Quick start

### Install

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.ps1 | iex
```

```bash
# Or build from source (requires Rust 1.75+)
cargo install --path crates/sigyn-cli
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

### Basic usage

```bash
# Create an identity (keypair)
sigyn identity create -n alice

# Create a vault for your project
sigyn vault create myapp

# Store secrets (use -v for vault, -e for env, -i for identity)
sigyn secret set DATABASE_URL "postgres://localhost/myapp" -v myapp -e dev
sigyn secret set API_KEY "sk-..." -e dev

# Retrieve a secret
sigyn secret get DATABASE_URL -e dev

# List all secrets in an environment
sigyn secret list -e dev

# Inject secrets into a process (never written to disk)
sigyn run -e dev -- ./start-server

# Or use a project config for zero-flag workflows (see below)
```

### Project config (`.sigyn.toml`)

Drop a `.sigyn.toml` in your project root to set per-project defaults:

```toml
[project]
vault = "myapp"
env = "dev"
identity = "alice"

[commands]
dev = "npm run dev"
app = "./start-server"
migrate = "python manage.py migrate"
```

Then simply:

```bash
sigyn run dev          # runs 'npm run dev' with secrets injected
sigyn run app --prod   # runs './start-server' with prod secrets
sigyn secret list      # uses vault/env/identity from .sigyn.toml
```

### Organizations

Group vaults into a hierarchical org structure with inherited RBAC. See [Organizations](docs-site/src/organizations.md) for details.

### Sync via Git

```bash
sigyn sync push
sigyn sync pull
```

---

## CI/CD Integration

Sigyn has a first-class [GitHub Action](docs-site/src/ci-cd.md) for injecting vault secrets into your pipelines.

### Setup

```bash
# Create a CI-specific identity
sigyn identity create --name ci-bot

# Invite it with minimal permissions
sigyn delegation invite create --role reader --envs staging,prod

# Generate a CI bundle (single base64 string)
sigyn ci setup ci-bot
```

Add three secrets to your GitHub repo: `SIGYN_CI_BUNDLE`, `SIGYN_PASSPHRASE`, and `VAULT_SSH_KEY`.

### GitHub Actions usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Load secrets
        uses: tonybenoy/sigyn/action@main
        with:
          bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
          passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
          vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
          vault-repo: git@github.com:myorg/sigyn-vaults.git
          vault: myapp
          environment: prod

      # All secrets are now available as environment variables
      - name: Deploy
        run: ./deploy.sh
```

The action supports multiple export modes (`env`, `dotenv`, `json`, `mask-only`), key filtering, and automatic log masking. See the [CI/CD guide](docs-site/src/ci-cd.md) for GitLab CI, generic CI platforms, and security best practices.

---

## Protecting Secrets from AI Coding Agents

AI coding assistants like Claude Code, GitHub Copilot, and Cursor run in your terminal and can read environment variables, `.env` files, and shell history. Sigyn keeps secrets out of their reach:

```bash
# BAD: secrets in .env or exported shell vars — visible to any agent
export DATABASE_URL="postgres://prod:secret@db.internal/myapp"

# GOOD: secrets injected only into the process that needs them
sigyn run -e prod -- ./myapp

# BEST: secrets served over a Unix socket — never in env vars at all
sigyn run serve -e prod &
```

| Method | How it works | Agent can see it? |
|--------|-------------|-------------------|
| `.env` files / `export` | Secrets in plaintext on disk or in shell | Yes |
| `sigyn run exec` | Injected as env vars into child process only | No (different process) |
| `sigyn run --clean` | Clean environment, only vault secrets | No |
| `sigyn run serve` | Served over Unix socket (0600 perms) | No (no env vars at all) |

Your workflow: run `sigyn run` for your app in one terminal, run your AI coding agent in another. The agent never sees your credentials because they were never in its environment.

See the [security documentation](docs-site/src/security.md) for details.

---

## Architecture

Sigyn is a Cargo workspace with four crates:

| Crate | Purpose |
|-------|---------|
| `sigyn-core` | Pure library (publishable): crypto, policy, CRDT, types -- zero I/O dependencies |
| `sigyn-engine` | I/O layer: filesystem, git sync, audit persistence -- depends on and re-exports `sigyn-core` |
| `sigyn-web` | Local web GUI: axum backend, embedded SPA, REST API |
| `sigyn-cli` | Binary (`sigyn`): CLI interface, TUI, web GUI, process injection, import/export |
| `sigyn-recovery` | Standalone binary (`sigyn-recovery`): Shamir shard management and vault recovery |

See the [`docs/`](docs/) directory for detailed design documents.

---

## CLI reference

```
sigyn <command>
```

| Command | Description |
|---------|-------------|
| `identity` | Manage identities (keypairs) |
| `vault` | Create and manage vaults |
| `secret` | Store, retrieve, list, and delete secrets |
| `env` | Manage environments (create, list, promote) |
| `policy` | Configure RBAC policies and constraints |
| `mfa` | Manage TOTP-based multi-factor authentication |
| `org` | Manage organizations and hierarchy (create, tree, policy, sync) |
| `delegation` | Invite members, revoke access, view delegation tree |
| `audit` | View and verify the signed audit trail |
| `sync` | Push, pull, and resolve sync conflicts |
| `fork` | Create and manage vault forks |
| `project` | Initialize and manage project config (`.sigyn.toml`) |
| `run` | Inject secrets into processes, export, or serve via socket |
| `rotate` | Rotate secrets, schedule rotation, breach mode |
| `import` | Import from Doppler, AWS, GCP, 1Password, dotenv, JSON |
| `ci` | Set up CI/CD identities and generate bundles |
| `notification` | Configure and test webhook notifications |
| `context` | Set persistent vault/env/identity context |
| `agent` | Passphrase caching agent (ssh-agent-like) |
| `watch` | Watch mode — auto-restart app on secret changes |
| `onboard` | Guided first-run setup wizard |
| `web` | Launch browser-based GUI for visual secret management |
| `tui` | Launch the interactive TUI dashboard |
| `update` | Self-update to the latest release |
| `doctor` | Run health checks |
| `status` | Show current vault, identity, environments, sync, and rotation info |
| `init` | Initialize default configuration (interactive: offers identity/vault creation) |
| `completions` | Generate shell completions (bash, zsh, fish, powershell) |

Run `sigyn <command> --help` for detailed usage of any command.

---

## Security model

- **Encryption at rest**: every secret value is encrypted with ChaCha20-Poly1305. Each environment has its own independent 256-bit key, sealed under each authorized member's X25519 public key (envelope encryption with per-environment key isolation).
- **Key derivation**: the user passphrase is processed through Argon2id to derive the wrapping key for the identity keypair.
- **Signing**: all audit log entries are signed with Ed25519. The log is hash-chained so any tampering is detectable.
- **Access control**: a seven-level RBAC hierarchy combined with per-key ACL constraints (time windows, expiry, MFA) governs who can read, write, or administer secrets.
- **Recovery**: the master key can be split into Shamir shards (K-of-N) and distributed to trusted parties for disaster recovery.

For a full threat model and cryptographic details, see [`docs-site/src/security.md`](docs-site/src/security.md).

---

## Import and export

### Import

```bash
sigyn import dotenv .env --env dev
sigyn import json secrets.json --env dev
sigyn import doppler --project myproject --config prd --env prod
sigyn import aws --secret-id myapp/prod --env prod --region us-east-1
sigyn import gcp --secret myapp-config --env prod --project my-gcp-project
sigyn import 1password --item "App Secrets" --vault "Engineering" --env dev
```

### Export

```bash
sigyn run export --env prod --format dotenv > .env
sigyn run export --env prod --format json > secrets.json
sigyn run export --env prod --format k8s > k8s-secret.yaml
sigyn run export --env prod --format docker > docker.env
sigyn run export --env prod --format shell  # eval-ready export statements
```

---

## Contributing

Contributions are welcome. To get started:

```bash
git clone https://github.com/tonybenoy/sigyn.git
cd sigyn
cargo build
cargo test --all --features sigyn-cli/fast-kdf
```

Please ensure `cargo clippy` and `cargo test --all --features sigyn-cli/fast-kdf` pass before submitting a
pull request. The CI pipeline enforces both.

## Documentation

- [**Getting Started**](docs-site/src/getting-started.md) — install and use Sigyn
- [**CLI Reference**](docs-site/src/cli-reference.md) — complete command documentation
- [**Configuration**](docs-site/src/configuration.md) — config files, resolution priority, directory layout
- [**Environments**](docs-site/src/environments.md) — per-environment key isolation
- [**Import and Export**](docs-site/src/import-export.md) — bring secrets in and out
- [**Multiple Vaults**](docs-site/src/multi-vault.md) — multi-vault and monorepo patterns
- [**Organizations**](docs-site/src/organizations.md) — hierarchical org structure and inherited RBAC
- [**CI/CD Integration**](docs-site/src/ci-cd.md) — GitHub Action, GitLab CI, and generic pipelines
- [**Team Collaboration**](docs-site/src/delegation.md) — delegation, invites, and offboarding
- [**Git Sync**](docs-site/src/sync.md) — sync and CRDT conflict resolution
- [**Forks**](docs-site/src/forks.md) — vault forking for team branches
- [**Security Model**](docs-site/src/security.md) — crypto primitives and threat model
- [**MFA**](docs-site/src/mfa.md) — TOTP multi-factor authentication
- [**Audit & Rotation**](docs-site/src/audit.md) — signed audit trail and secret rotation
- [**Disaster Recovery**](docs-site/src/recovery.md) — Shamir secret sharing
- [**Architecture**](docs-site/src/architecture.md) — deep dive into how it works
- [**Examples**](docs-site/src/examples.md) — real-world recipes and workflows
- [**FAQ**](docs-site/src/FAQ.md) — frequently asked questions
- [**Development Guide**](docs-site/src/DEVELOPMENT.md) — hacking on Sigyn
- [**Testing**](docs-site/src/testing.md) — running and writing tests
- [**Contributing**](CONTRIBUTING.md) — how to contribute

---

## Developer Quick Start

If you want to contribute to Sigyn, here is how to get started:

```bash
# Clone the repo
git clone https://github.com/tonybenoy/sigyn.git
cd sigyn

# Run all tests
cargo test

# Run the CLI from source
cargo run -- vault list

# Check for linting issues
cargo clippy -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

---

## License

Sigyn is released under the [MIT License](LICENSE).
