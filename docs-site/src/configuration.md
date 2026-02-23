# Configuration

Sigyn stores its configuration and data under `~/.sigyn/`.

## Directory Layout

```
~/.sigyn/
├── config.toml                    # Global configuration
├── identities/
│   └── <fingerprint>.identity     # Encrypted identity files
└── vaults/
    └── <vault-name>/
        ├── vault.toml             # Vault manifest (unencrypted metadata)
        ├── members.cbor           # Envelope header (encrypted master key slots)
        ├── policy.cbor            # Encrypted policy blob
        ├── envs/
        │   ├── dev.vault          # Encrypted environment files (CBOR)
        │   ├── staging.vault
        │   └── prod.vault
        ├── audit.log.json         # Append-only audit log (JSON Lines)
        └── forks.cbor             # Fork registry
```

## config.toml

The global configuration file is created with `sigyn init`:

```bash
sigyn init --identity alice --vault myapp
```

```toml
default_identity = "alice"
default_vault = "myapp"
```

## Global CLI Flags

These flags override config file defaults for a single invocation:

| Flag | Description |
|------|-------------|
| `--vault <name>` | Override the default vault |
| `--env <name>` | Override the default environment |
| `--identity <name>` | Override the default identity |
| `--json` | Output as JSON instead of formatted text |
| `--quiet` | Suppress non-essential output |
| `--dry-run` | Preview changes without applying |

## vault.toml

Each vault has a manifest file with unencrypted metadata:

```toml
vault_id = "550e8400-e29b-41d4-a716-446655440000"
name = "myapp"
owner = "a1b2c3d4e5f6..."
environments = ["dev", "staging", "prod"]
created_at = "2025-03-15T10:30:00Z"
```

This file is safe to commit to git — it contains no secrets.

## Shell Completions

Generate completions for your shell:

```bash
# Bash
sigyn completions bash >> ~/.bashrc

# Zsh
sigyn completions zsh >> ~/.zshrc

# Fish
sigyn completions fish > ~/.config/fish/completions/sigyn.fish

# PowerShell
sigyn completions powershell >> $PROFILE
```

## Health Check

Run `sigyn doctor` to verify your installation:

```bash
sigyn doctor
```

This checks:
- Identity files exist and are readable
- Default vault is accessible
- Audit chain integrity
- Expiring secrets
- Sync status
