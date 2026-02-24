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

## Security

### Is my passphrase stored anywhere?

No. Your passphrase is processed through Argon2id to derive a key that decrypts your private keys. The passphrase itself is never written to disk or stored in memory beyond the current operation.

### What happens if I lose my passphrase?

If you lose your passphrase and haven't set up Shamir recovery shards, your secrets are permanently inaccessible. Set up recovery shards immediately after creating an identity:

```bash
sigyn-recovery split --identity alice --threshold 3 --total 5
```

### Are my secrets encrypted in git?

Yes. Every secret is encrypted with ChaCha20-Poly1305 before being committed to git. Even with full access to the git repository, secrets cannot be read without an authorized private key.

### Is it safe to commit `.sigyn.toml` to my repository?

Yes. The `.sigyn.toml` project config only contains vault/environment/identity names and command aliases -- never secret values. It's designed to be committed and shared with your team.

## Usage

### How do I inject secrets into my application?

Use the `sigyn run` command:

```bash
sigyn run -e dev -- ./my-app
sigyn run --prod -- docker compose up
```

Secrets are passed directly as environment variables to the child process without writing them to disk.

### How do I set up Sigyn for an existing project?

Run `sigyn project init` in your project root:

```bash
sigyn project init
```

This interactively creates a `.sigyn.toml` with your vault and identity. Then import your existing `.env` file:

```bash
sigyn import dotenv .env -e dev
```

### Can I use Sigyn in CI/CD?

Yes. Use `sigyn run` to inject secrets at build time, or `sigyn run export` to generate a `.env` file:

```bash
# Inject directly
sigyn run --staging -- ./scripts/run-tests.sh

# Or export to a file
sigyn run export -e staging -f dotenv > .env
```

You'll need to provide the CI runner with an authorized identity file.

### How do I share secrets with my team?

1. Your teammate creates an identity: `sigyn identity create -n bob`
2. They share their fingerprint with you
3. You add them to the vault: `sigyn policy member-add <fingerprint> --role contributor`
4. Push and pull via git: `sigyn sync push` / `sigyn sync pull`

### What happens if two people edit a secret at the same time?

Sigyn uses vector clocks and CRDTs (Conflict-free Replicated Data Types) to resolve conflicts deterministically. By default, Last-Write-Wins (LWW) is used, but you can manually resolve conflicts with `sigyn sync resolve`.
