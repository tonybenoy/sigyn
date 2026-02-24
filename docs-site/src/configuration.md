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

For per-project defaults, create a `.sigyn.toml` file in your project root. This
eliminates the need to pass `--vault`, `--env`, and `--identity` flags on every command.

Sigyn searches for this file starting in the current directory and walking up to parent
directories, so it works from any subdirectory of your project.

You can also place the same file at `~/.sigyn/project.toml` as a user-level fallback
(useful for defaults you don't want to commit to a repo). The project-local file
takes precedence over the user-level one.

### Creating a project config

The easiest way is to use `sigyn project init`:

```bash
# Interactive — prompts for vault and identity
sigyn project init

# Non-interactive
sigyn project init -v myapp -e dev -i alice

# Write to ~/.sigyn/project.toml instead (user-level fallback)
sigyn project init --global
```

Or create `.sigyn.toml` by hand:

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

This file is safe to commit to git — it contains no secrets, only references to vault
and identity names.

### `[project]` table

| Key | Type | Description |
|-----|------|-------------|
| `vault` | string | Default vault for this project |
| `env` | string | Default environment for this project |
| `identity` | string | Default identity for this project |

All fields are optional. You can specify just the ones you want as defaults. For example,
if everyone on your team uses the same vault but different identities:

```toml
[project]
vault = "myapp"
env = "dev"
```

### `[commands]` table

Named commands that can be invoked with `sigyn run <name>`. The value is the command
string to execute with secrets injected as environment variables. Extra arguments
passed after the command name are appended to the command string.

```toml
[commands]
dev = "npm run dev"
app = "./start-server"
migrate = "python manage.py migrate"
test = "cargo test"
db = "psql"
```

```bash
sigyn run dev              # runs 'npm run dev' with secrets
sigyn run app --prod       # runs './start-server' with prod env secrets
sigyn run migrate          # runs 'python manage.py migrate' with secrets
sigyn run test -- --lib    # runs 'cargo test --lib' with secrets
```

The `--prod` and `--staging` flags are shorthand for `--env prod` and `--env staging`:

```bash
sigyn run dev --prod       # overrides the default env to prod
```

### Resolution priority

Settings are resolved in this order (highest to lowest):

1. CLI flags (`--vault`, `-v`, `--env`, `-e`, `--identity`, `-i`)
2. Project config (`.sigyn.toml` in current or parent directory)
3. User project config (`~/.sigyn/project.toml`)
4. Global config (`~/.sigyn/config.toml`)
5. Hardcoded defaults

### Example workflows

**Zero-flag daily usage:**

```bash
# With .sigyn.toml in your project root, just:
sigyn secret list              # lists secrets in default vault/env
sigyn secret get DATABASE_URL  # gets a secret from default vault/env
sigyn run dev                  # starts dev server with secrets injected
```

**Multiple environments:**

```bash
# .sigyn.toml defaults to dev, override per-command:
sigyn secret list --prod
sigyn run app --staging
sigyn secret get API_KEY -e prod
```

**Monorepo with multiple services:**

```
monorepo/
├── .sigyn.toml          # vault = "shared", env = "dev"
├── services/
│   ├── api/
│   │   └── .sigyn.toml  # vault = "api-service", env = "dev"
│   └── web/
│       └── .sigyn.toml  # vault = "web-app", env = "dev"
```

Each service can have its own `.sigyn.toml` pointing to a different vault. Sigyn finds
the nearest config file by walking up from the current directory.

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
