# Configuration

Sigyn stores its configuration and data under `~/.sigyn/`.

## Directory Layout

```
~/.sigyn/
├── config.toml                    # Global configuration
├── project.toml                   # User-level project defaults (optional)
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

## Project Config (`.sigyn.toml`)

For per-project defaults, create a `.sigyn.toml` file in your project root. Sigyn
searches for this file in the current directory and walks up to parent directories.

You can also place the same file at `~/.sigyn/project.toml` as a user-level fallback
(useful for defaults you don't want to commit to a repo). The project-local file
takes precedence over the user-level one.

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

### `[project]` table

| Key | Description |
|-----|-------------|
| `vault` | Default vault for this project |
| `env` | Default environment for this project |
| `identity` | Default identity for this project |

### `[commands]` table

Named commands that can be invoked with `sigyn run <name>`. The value is the command
string to execute with secrets injected. Extra arguments are appended.

```bash
sigyn run dev              # runs 'npm run dev' with secrets
sigyn run app --prod       # runs './start-server' with prod env
sigyn run migrate          # runs 'python manage.py migrate' with secrets
```

### Resolution priority

Settings are resolved in this order (highest to lowest):

1. CLI flags (`--vault`, `-v`, `--env`, `-e`, etc.)
2. Project config (`.sigyn.toml` in project directory)
3. User project config (`~/.sigyn/project.toml`)
4. Global config (`~/.sigyn/config.toml`)
5. Hardcoded defaults

## Global CLI Flags

These flags override config file defaults for a single invocation:

| Flag | Short | Description |
|------|-------|-------------|
| `--vault <name>` | `-v` | Override the default vault |
| `--env <name>` | `-e` | Override the default environment |
| `--identity <name>` | `-i` | Override the default identity |
| `--json` | | Output as JSON instead of formatted text |
| `--quiet` | | Suppress non-essential output |
| `--dry-run` | | Preview changes without applying |

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
