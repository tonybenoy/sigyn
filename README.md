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
- **Per-environment secrets** -- first-class support for dev, staging, production, and custom environments.
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
- **Self-update** -- `sigyn update` downloads and installs the latest release with checksum verification.
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

Group vaults into a hierarchical org structure with inherited RBAC:

```bash
# Create an org and sub-teams
sigyn org create acme
sigyn org node create platform --parent acme --type division
sigyn org node create web --parent acme/platform --type team

# Create a vault under an org node
sigyn vault create myapp --org acme/platform/web

# Link an existing vault to an org
sigyn vault attach legacy-app --org acme

# View the hierarchy
sigyn org tree

# Add an org-level admin (inherits access to all child nodes and vaults)
sigyn org policy member-add <fingerprint> --role admin --path acme

# Check effective permissions
sigyn org policy effective <fingerprint> --path acme/platform/web
```

Members added at a higher org level automatically gain access to all child nodes and vaults. The highest role across all levels wins, and environment/pattern permissions are unioned.

### Sync via Git

```bash
sigyn sync push
sigyn sync pull
```

---

## Architecture

Sigyn is a Cargo workspace with three crates:

| Crate | Purpose |
|-------|---------|
| `sigyn-core` | Library: crypto, vault, RBAC, sync, audit, CRDT engine |
| `sigyn-cli` | Binary (`sigyn`): CLI interface, TUI, process injection, import/export |
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
| `tui` | Launch the interactive TUI dashboard |
| `update` | Self-update to the latest release |
| `doctor` | Run health checks |
| `status` | Show current vault and environment info |
| `init` | Initialize default configuration |
| `completions` | Generate shell completions (bash, zsh, fish, powershell) |

Run `sigyn <command> --help` for detailed usage of any command.

---

## Security model

- **Encryption at rest**: every secret value is encrypted with ChaCha20-Poly1305. A unique data encryption key (DEK) is generated per secret and sealed under the recipient's X25519 public key (envelope encryption).
- **Key derivation**: the user passphrase is processed through Argon2id to derive the master secret.
- **Signing**: all audit log entries are signed with Ed25519. The log is hash-chained so any tampering is detectable.
- **Access control**: a seven-level RBAC hierarchy combined with per-key ACL constraints (time windows, expiry, MFA) governs who can read, write, or administer secrets.
- **Recovery**: the master key can be split into Shamir shards (K-of-N) and distributed to trusted parties for disaster recovery.

For a full threat model and cryptographic details, see [`docs/security.md`](docs/security.md).

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

- [**Getting Started**](docs/getting-started.md) — install and use Sigyn
- [**CLI Reference**](docs/cli-reference.md) — complete command documentation
- [**Examples**](docs/examples.md) — real-world recipes and workflows
- [**FAQ**](docs/FAQ.md) — frequently asked questions
- [**Architecture**](docs/architecture.md) — deep dive into how it works
- [**Security Model**](docs/security.md) — crypto primitives and threat model
- [**Development Guide**](docs/DEVELOPMENT.md) — hacking on Sigyn
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
