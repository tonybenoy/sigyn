<p align="center">
  <img src="logo.png" alt="Sigyn" width="200">
</p>

# Sigyn

**Serverless encrypted P2P secret manager**

Sigyn is a command-line tool for managing application secrets — API keys, database credentials, certificates, and other sensitive configuration. Unlike hosted secret managers, Sigyn requires no server infrastructure. Secrets are encrypted at rest, stored locally, and synced between team members via git.

## The Name

In Norse mythology, Sigyn is the goddess of fidelity and devotion — she faithfully holds a bowl over her bound husband Loki to shield him from venom. Sigyn the tool does the same for your secrets: it stands guard over your sensitive data, shielding it from exposure with steadfast encryption and access control. Loyalty, protection, and quiet reliability.

## Why Sigyn?

- **No server required.** Secrets live in encrypted files synced through git. No SaaS dependency, no infrastructure to maintain.
- **End-to-end encrypted.** Secrets are sealed with X25519 envelope encryption and encrypted with ChaCha20-Poly1305. Only authorized members can decrypt.
- **Fine-grained access control.** Seven-level role hierarchy, per-key ACLs, time-window constraints, IP allowlists, and automatic expiry.
- **Auditable.** Every operation is recorded in a hash-chained, Ed25519-signed audit log. Tamper detection is built in.
- **Team-ready.** Invite members, delegate access, fork vaults, and revoke access with automatic cascade — all without a central authority.

## Quick Example

```bash
# Create an identity
sigyn identity create --name alice

# Create a vault for your project
sigyn vault create myapp

# Add secrets
sigyn secret set DATABASE_URL 'postgres://localhost/myapp' --env dev
sigyn secret set API_KEY 'sk-...' --env dev

# Run your app with secrets injected
sigyn run exec --env dev -- ./myapp

# Share with a teammate
sigyn delegation invite create --pubkey <fingerprint> --role contributor
```

## Documentation

Use the sidebar to navigate through the documentation. Start with [Getting Started](./getting-started.md) for a step-by-step tutorial, or jump to the [CLI Reference](./cli-reference.md) for the full command listing.
