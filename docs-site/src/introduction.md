<p align="center">
  <img src="logo.png" alt="Sigyn - Open Source Secret Manager" width="200">
</p>

# Sigyn: Serverless Encrypted Secret Manager

Sigyn is an open-source, serverless secret manager that keeps your API keys, database credentials, and application secrets encrypted at rest and synced via git -- with no server required.

Think of it as a self-hosted alternative to Doppler, AWS Secrets Manager, or HashiCorp Vault -- but fully peer-to-peer, git-native, and zero-infrastructure.

## Key Features

- **End-to-end encryption.** Secrets are sealed with X25519 envelope encryption and encrypted with ChaCha20-Poly1305. Only authorized team members can decrypt.
- **No server, no SaaS.** Secrets are encrypted files in a git repository. No hosted infrastructure to manage, no vendor lock-in, no monthly bills.
- **Role-based access control.** Seven-level role hierarchy (ReadOnly through Owner), per-key ACLs, time-window constraints, and automatic expiry.
- **Git-native sync.** Push and pull secrets just like code. CRDT-based conflict resolution handles concurrent edits.
- **Per-environment secrets.** First-class support for dev, staging, production, and custom environments.
- **Team collaboration.** Invite members, delegate access with cascade revocation, and track every operation in a signed audit trail.
- **Process injection.** `sigyn run -- ./app` injects secrets as environment variables without writing them to disk.
- **AI-agent safe.** Secrets stay out of your shell environment where coding agents run. Use `sigyn run serve` for zero-exposure secret access.
- **Web GUI.** Browser-based dashboard for visual secret management (`sigyn web`).
- **Project config.** Drop a `.sigyn.toml` in your project root for zero-flag workflows and named run commands.
- **Cross-platform.** One-liner install for macOS, Linux, and Windows.

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh

# Create an identity and vault
sigyn identity create -n alice
sigyn vault create myapp

# Store and retrieve secrets
sigyn secret set DATABASE_URL 'postgres://localhost/myapp' -v myapp -e dev
sigyn secret get DATABASE_URL -e dev

# Set up project config
sigyn project init

# Run your app with secrets injected
sigyn run -- ./myapp
```

## Who Is Sigyn For?

- **Solo developers** who want encrypted secret management without SaaS dependencies
- **Small teams** that need to share secrets securely via git without setting up Vault or paying for Doppler
- **Security-conscious organizations** that require audit trails, RBAC, and self-hosted secret storage
- **CI/CD pipelines** that need secrets injected at runtime without writing `.env` files to disk
- **AI-assisted development** where coding agents (Claude Code, Cursor, Copilot) run in your terminal and you need to keep credentials out of their reach

## The Name

In Norse mythology, Sigyn is the goddess of fidelity and devotion -- she faithfully holds a bowl over her bound husband Loki to shield him from venom. Sigyn the tool does the same for your secrets: it stands guard over your sensitive data with steadfast encryption and access control.

## Next Steps

- [Getting Started](./getting-started.md) -- install Sigyn and create your first vault
- [CLI Reference](./cli-reference.md) -- complete command documentation
- [Configuration](./configuration.md) -- global and project config options
- [Security Model](./security.md) -- cryptographic design and threat model
- [Examples](./examples.md) -- CI/CD integration, Docker, and team workflows
