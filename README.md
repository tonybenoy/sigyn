<p align="center">
  <img src="assets/logo.png" alt="Sigyn" width="200">
</p>

<h1 align="center">Sigyn</h1>

<p align="center"><strong>Serverless, encrypted, peer-to-peer secret management.</strong></p>

[![CI](https://github.com/tonybenoy/sigyn/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybenoy/sigyn/actions/workflows/ci.yml)
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
- **Per-key ACLs** -- granular constraints including time windows, IP allowlists, rate limits, and expiry.
- **Signed audit trail** -- hash-chained, Ed25519-signed log of every secret operation.
- **Disaster recovery** -- Shamir secret sharing splits the master key into K-of-N shards.
- **Fork system** -- leashed and unleashed forks for team branches and experimentation.
- **Rotation scheduling** -- cron-based automatic rotation with breach mode for emergency re-key.
- **Import/export** -- bring secrets in from Doppler, AWS Secrets Manager, GCP Secret Manager, 1Password, or `.env` files; export to dotenv, JSON, Kubernetes secrets, Docker env, or shell eval.
- **Process injection** -- `sigyn run -- cmd` injects secrets as environment variables without writing them to disk.
- **Unix socket server** -- programmatic access for scripts and CI pipelines.
- **Interactive TUI** -- ratatui-powered dashboard for browsing and managing secrets.
- **LAN peer discovery** -- find and sync with teammates on the local network.
- **Shell completions** -- bash, zsh, fish, and PowerShell.

---

## Quick start

### Install from source

```bash
# Requires Rust 1.75+
cargo install --path crates/sigyn-cli
```

### Basic usage

```bash
# Create an identity (keypair)
sigyn identity create --name alice

# Create a vault for your project
sigyn vault create myapp

# Store secrets
sigyn secret set DATABASE_URL "postgres://localhost/myapp" --env dev
sigyn secret set API_KEY "sk-..." --env dev

# Retrieve a secret
sigyn secret get DATABASE_URL --env dev

# List all secrets in an environment
sigyn secret list --env dev

# Inject secrets into a process (never written to disk)
sigyn run exec --env dev -- ./start-server
```

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
| `delegation` | Invite members, revoke access, view delegation tree |
| `audit` | View and verify the signed audit trail |
| `sync` | Push, pull, and resolve sync conflicts |
| `fork` | Create and manage vault forks |
| `run` | Inject secrets into processes, export, or serve via socket |
| `rotate` | Rotate secrets, schedule rotation, breach mode |
| `import` | Import from Doppler, AWS, GCP, 1Password, dotenv, JSON |
| `tui` | Launch the interactive TUI dashboard |
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
- **Access control**: a seven-level RBAC hierarchy combined with per-key ACL constraints (time windows, IP allowlists, rate limits, expiry) governs who can read, write, or administer secrets.
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
cargo test
```

Please ensure `cargo clippy` and `cargo test` pass before submitting a
pull request. The CI pipeline enforces both.

---

## License

Sigyn is released under the [MIT License](LICENSE).
