# CI/CD Integration

Sigyn provides first-class CI/CD support so your pipelines can decrypt and use vault secrets without storing them in plaintext. This page covers the official integrations for GitHub Actions, GitLab CI/CD, and Bitbucket Pipelines, along with generic CI setup, security best practices, and troubleshooting.

## Overview

The CI/CD workflow has three components:

1. **CI identity** — a dedicated Sigyn identity for your pipeline (least-privilege, scoped to specific environments)
2. **CI bundle** — a single base64 string containing the identity file, device key, and fingerprint
3. **Secret injection** — the action (or manual steps) clones the vault, decrypts secrets, and makes them available to your workflow

## Quick Start

### 1. Create a CI identity

Create a dedicated identity for your CI pipeline. Use a separate identity per repo or team — never reuse your personal identity.

```bash
# Create a CI-specific identity
sigyn identity create --name ci-bot

# Invite it to the vault with minimal permissions
sigyn delegation invite create --role reader --envs staging,prod

# Accept the invite on the CI identity, then generate the bundle
sigyn ci setup ci-bot
```

The `sigyn ci setup` command outputs a single `SIGYN_CI_BUNDLE` value. Use `--json` for machine-readable output.

### 2. Configure repository secrets

Add **3 secrets** to your repository (Settings > Secrets and variables > Actions):

| GitHub Secret | Source | Description |
|---------------|--------|-------------|
| `SIGYN_CI_BUNDLE` | Output of `sigyn ci setup` | Base64-encoded JSON containing identity file, device key, and fingerprint |
| `SIGYN_PASSPHRASE` | Your CI identity's passphrase | Used to decrypt the identity's private key |
| `VAULT_SSH_KEY` | SSH deploy key for the vault repo | Must have read access to clone the vault repository |

> **Tip:** Use a dedicated SSH deploy key (not a personal key) with read-only access to the vault repository. Generate one with `ssh-keygen -t ed25519 -C "sigyn-ci"` and add it under the vault repo's Settings > Deploy Keys.

### 3. Add the action to your workflow

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

## GitHub Action Reference

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `bundle` | Yes | — | CI bundle from `sigyn ci setup` |
| `passphrase` | Yes | — | Identity passphrase |
| `vault-ssh-key` | Yes | — | SSH private key for cloning the vault repo |
| `vault-repo` | Yes | — | Git URL for the vault repository (e.g., `git@github.com:myorg/vaults.git`) |
| `vault` | Yes | — | Vault name |
| `environment` | Yes | — | Environment name (e.g., `dev`, `staging`, `prod`) |
| `export` | No | `env` | Export mode: `env`, `dotenv`, `json`, or `mask-only` |
| `dotenv-path` | No | `.env` | Output path for `dotenv` or `json` export modes (must be a relative path) |
| `keys` | No | `""` (all) | Comma-separated list of specific secret keys to export |
| `mask` | No | `true` | Mask all secret values in GitHub Actions logs |
| `version` | No | `latest` | Sigyn version to install |

### Outputs

| Output | Description |
|--------|-------------|
| `secrets-json` | Compact JSON of exported secrets (`env`/`json` modes only). **Warning:** accessible to all subsequent steps in the job — use key filtering to limit exposure. |
| `count` | Number of secrets exported |

### Export Modes

| Mode | Behavior |
|------|----------|
| `env` (default) | Writes secrets to `$GITHUB_ENV` — available as environment variables in all subsequent steps |
| `dotenv` | Writes a `.env` file to the path specified by `dotenv-path` |
| `json` | Writes a JSON file to the path specified by `dotenv-path`; also sets `secrets-json` output |
| `mask-only` | Masks secret values in GitHub Actions logs but does not export them anywhere |

### What the Action Does

The composite action performs five steps:

1. **Install Sigyn** — downloads and installs the Sigyn binary (prefers the install script bundled with the action ref; version controlled via the `version` input)
2. **Restore identity** — decodes the CI bundle, validates the fingerprint format, writes the identity file and device key to `$SIGYN_HOME`
3. **Clone vault** — validates the vault name, fetches SSH host keys for github.com/gitlab.com, uses the provided SSH key to clone (or pull) the vault repository with strict host key checking
4. **Export secrets** — runs `sigyn run export --format json`, optionally filters by key, masks values in logs, and writes to the chosen destination
5. **Cleanup** — removes identity files, device key, vault data, and SSH keys from the runner (runs even if previous steps fail)

## Examples

### Basic deployment

```yaml
- name: Load secrets
  uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-repo: git@github.com:myorg/sigyn-vaults.git
    vault: myapp
    environment: prod

- name: Deploy
  run: |
    echo "Deploying with database at $DATABASE_URL"
    ./deploy.sh
```

### Filtering specific keys

Export only the secrets your step needs:

```yaml
- name: Load AWS credentials
  uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-repo: git@github.com:myorg/sigyn-vaults.git
    vault: infra
    environment: prod
    keys: "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_DEFAULT_REGION"

- name: Login to ECR
  run: aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REGISTRY
```

### Writing a `.env` file

Useful for frameworks that read from `.env`:

```yaml
- name: Load secrets as dotenv
  uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-repo: git@github.com:myorg/sigyn-vaults.git
    vault: myapp
    environment: staging
    export: dotenv
    dotenv-path: .env.staging

- name: Run tests
  run: npm test
```

### Using outputs in subsequent steps

```yaml
- name: Load secrets
  id: secrets
  uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-repo: git@github.com:myorg/sigyn-vaults.git
    vault: myapp
    environment: prod

- name: Report
  run: echo "Loaded ${{ steps.secrets.outputs.count }} secrets"
```

### Multiple vaults in one workflow

```yaml
- name: Load shared infrastructure secrets
  uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-repo: git@github.com:myorg/sigyn-vaults.git
    vault: shared-infra
    environment: prod

- name: Load app-specific secrets
  uses: tonybenoy/sigyn/action@main
  with:
    bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
    passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
    vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
    vault-repo: git@github.com:myorg/sigyn-vaults.git
    vault: myapp
    environment: prod
```

When loading from multiple vaults, secrets from later steps override earlier ones if the keys overlap (since both write to `$GITHUB_ENV`).

### Environment matrix

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        env: [dev, staging]
    steps:
      - uses: actions/checkout@v4

      - name: Load secrets for ${{ matrix.env }}
        uses: tonybenoy/sigyn/action@main
        with:
          bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
          passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
          vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
          vault-repo: git@github.com:myorg/sigyn-vaults.git
          vault: myapp
          environment: ${{ matrix.env }}

      - name: Run tests
        run: npm test
```

## Other CI Platforms

### GitLab CI

Sigyn provides an official GitLab CI/CD template that you can include directly in your `.gitlab-ci.yml`. It handles installation, identity restoration, vault cloning, secret export, and cleanup — the same five steps as the GitHub Action.

#### Quick start

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/tonybenoy/sigyn/main/action/gitlab-ci-template.yml'

deploy:
  extends: .sigyn-secrets
  variables:
    SIGYN_VAULT: myapp
    SIGYN_ENVIRONMENT: prod
    SIGYN_VAULT_REPO: git@gitlab.com:myorg/sigyn-vaults.git
  script:
    - echo "Deploying with $DATABASE_URL"
    - ./deploy.sh
```

#### Configure CI/CD variables

Add these as **masked and protected** variables in Settings > CI/CD > Variables:

| Variable | Description |
|----------|-------------|
| `SIGYN_CI_BUNDLE` | Output of `sigyn ci setup` (base64-encoded JSON) |
| `SIGYN_PASSPHRASE` | CI identity passphrase |
| `VAULT_SSH_KEY` | SSH private key for cloning the vault repo |

#### Template variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SIGYN_VAULT` | Yes | — | Vault name |
| `SIGYN_ENVIRONMENT` | Yes | — | Environment name (e.g. `dev`, `staging`, `prod`) |
| `SIGYN_VAULT_REPO` | Yes | — | Git URL for the vault repository |
| `SIGYN_EXPORT_MODE` | No | `dotenv` | Export mode: `env`, `dotenv`, or `json` |
| `SIGYN_DOTENV_PATH` | No | `.env` | Output path for dotenv/json export |
| `SIGYN_KEYS` | No | `""` (all) | Comma-separated list of specific keys to export |
| `SIGYN_VERSION` | No | `latest` | Sigyn version to install |
| `SIGYN_INSTALL_URL` | No | GitHub | Override URL for `install.sh` (for self-hosted or mirrored setups) |

> **Note:** The template downloads `install.sh` and release binaries from GitHub by default. If your GitLab runners cannot reach `github.com`, set `SIGYN_INSTALL_URL` to a self-hosted mirror, or pre-install the `sigyn` binary in your CI image.

#### Export modes

| Mode | Behavior |
|------|----------|
| `env` | Sources secrets into the current shell environment and creates a `sigyn.env` [dotenv artifact](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportsdotenv) so downstream jobs can consume them via `needs:` |
| `dotenv` (default) | Writes a `.env` file to `SIGYN_DOTENV_PATH` |
| `json` | Writes a JSON file to `SIGYN_DOTENV_PATH` |

#### Passing secrets to downstream jobs

When using `env` mode, the template automatically creates a [dotenv artifact report](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportsdotenv). Downstream jobs can consume the variables:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/tonybenoy/sigyn/main/action/gitlab-ci-template.yml'

load-secrets:
  extends: .sigyn-secrets
  variables:
    SIGYN_VAULT: myapp
    SIGYN_ENVIRONMENT: prod
    SIGYN_VAULT_REPO: git@gitlab.com:myorg/sigyn-vaults.git
    SIGYN_EXPORT_MODE: env
  script:
    - echo "Secrets loaded"

deploy:
  stage: deploy
  needs: [load-secrets]
  script:
    # DATABASE_URL and other secrets are available here
    - ./deploy.sh
```

#### GitLab environment matrix

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/tonybenoy/sigyn/main/action/gitlab-ci-template.yml'

.test-template:
  extends: .sigyn-secrets
  variables:
    SIGYN_VAULT: myapp
    SIGYN_VAULT_REPO: git@gitlab.com:myorg/sigyn-vaults.git
  script:
    - npm test

test-staging:
  extends: .test-template
  variables:
    SIGYN_ENVIRONMENT: staging

test-prod:
  extends: .test-template
  variables:
    SIGYN_ENVIRONMENT: prod
  environment:
    name: production
```

#### What the template does

The `.sigyn-secrets` hidden job provides `before_script` and `after_script` blocks:

1. **Install Sigyn** — downloads and installs the Sigyn binary
2. **Restore identity** — decodes the CI bundle, validates the fingerprint, writes identity and device key
3. **Clone vault** — validates the vault name, sets up SSH with strict host key checking, clones the vault
4. **Export secrets** — runs `sigyn run export --format json`, optionally filters by key, writes to the chosen destination
5. **Cleanup** (`after_script`) — removes identity files, device key, vault data, and SSH keys (runs even on failure)

### Bitbucket Pipelines

Sigyn provides a Bitbucket Pipe that you can use directly in your `bitbucket-pipelines.yml`.

#### Quick start

```yaml
pipelines:
  default:
    - step:
        name: Deploy
        script:
          - pipe: docker://tonybenoy/sigyn-pipe:latest
            variables:
              SIGYN_CI_BUNDLE: $SIGYN_CI_BUNDLE
              SIGYN_PASSPHRASE: $SIGYN_PASSPHRASE
              VAULT_SSH_KEY: $VAULT_SSH_KEY
              VAULT_REPO: "git@bitbucket.org:myorg/sigyn-vaults.git"
              VAULT: "myapp"
              ENVIRONMENT: "prod"
          - source .env  # load the exported secrets
          - ./deploy.sh
```

Alternatively, run the pipe script directly without Docker:

```yaml
pipelines:
  default:
    - step:
        name: Deploy
        script:
          - curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/action/bitbucket-pipe/pipe.sh | bash
          - source .env
          - ./deploy.sh
```

#### Configure repository variables

Add these as **secured** variables in Repository Settings > Pipelines > Repository variables:

| Variable | Description |
|----------|-------------|
| `SIGYN_CI_BUNDLE` | Output of `sigyn ci setup` (base64-encoded JSON) |
| `SIGYN_PASSPHRASE` | CI identity passphrase |
| `VAULT_SSH_KEY` | SSH private key for cloning the vault repo |

#### Pipe variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_REPO` | Yes | — | Git URL for the vault repository |
| `VAULT` | Yes | — | Vault name |
| `ENVIRONMENT` | Yes | — | Environment name (e.g. `dev`, `staging`, `prod`) |
| `EXPORT_MODE` | No | `dotenv` | Export mode: `env`, `dotenv`, or `json` |
| `DOTENV_PATH` | No | `.env` | Output path for dotenv/json export |
| `KEYS` | No | `""` (all) | Comma-separated list of specific keys to export |
| `VERSION` | No | `latest` | Sigyn version to install |
| `SIGYN_INSTALL_URL` | No | GitHub | Override URL for `install.sh` (for self-hosted or mirrored setups) |

> **Note:** The pipe downloads `install.sh` and release binaries from GitHub by default. If your Bitbucket runners cannot reach `github.com`, set `SIGYN_INSTALL_URL` to a self-hosted mirror, or use a custom Docker image with `sigyn` pre-installed.

#### Examples

**Filtering specific keys:**

```yaml
- pipe: docker://tonybenoy/sigyn-pipe:latest
  variables:
    SIGYN_CI_BUNDLE: $SIGYN_CI_BUNDLE
    SIGYN_PASSPHRASE: $SIGYN_PASSPHRASE
    VAULT_SSH_KEY: $VAULT_SSH_KEY
    VAULT_REPO: "git@bitbucket.org:myorg/sigyn-vaults.git"
    VAULT: "infra"
    ENVIRONMENT: "prod"
    KEYS: "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY"
```

**JSON export:**

```yaml
- pipe: docker://tonybenoy/sigyn-pipe:latest
  variables:
    SIGYN_CI_BUNDLE: $SIGYN_CI_BUNDLE
    SIGYN_PASSPHRASE: $SIGYN_PASSPHRASE
    VAULT_SSH_KEY: $VAULT_SSH_KEY
    VAULT_REPO: "git@bitbucket.org:myorg/sigyn-vaults.git"
    VAULT: "myapp"
    ENVIRONMENT: "staging"
    EXPORT_MODE: "json"
    DOTENV_PATH: "secrets.json"
```

**Deployment environments:**

```yaml
pipelines:
  branches:
    staging:
      - step:
          name: Deploy to staging
          deployment: staging
          script:
            - pipe: docker://tonybenoy/sigyn-pipe:latest
              variables:
                SIGYN_CI_BUNDLE: $SIGYN_CI_BUNDLE
                SIGYN_PASSPHRASE: $SIGYN_PASSPHRASE
                VAULT_SSH_KEY: $VAULT_SSH_KEY
                VAULT_REPO: "git@bitbucket.org:myorg/sigyn-vaults.git"
                VAULT: "myapp"
                ENVIRONMENT: "staging"
            - source .env
            - ./deploy.sh
    main:
      - step:
          name: Deploy to production
          deployment: production
          script:
            - pipe: docker://tonybenoy/sigyn-pipe:latest
              variables:
                SIGYN_CI_BUNDLE: $SIGYN_CI_BUNDLE
                SIGYN_PASSPHRASE: $SIGYN_PASSPHRASE
                VAULT_SSH_KEY: $VAULT_SSH_KEY
                VAULT_REPO: "git@bitbucket.org:myorg/sigyn-vaults.git"
                VAULT: "myapp"
                ENVIRONMENT: "prod"
            - source .env
            - ./deploy.sh
```

### Generic CI (CircleCI, Jenkins, etc.)

The manual setup follows the same pattern used by all the platform integrations:

1. Install Sigyn: `curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh`
2. Decode the bundle and restore identity files
3. Clone the vault repo
4. Run `sigyn run export` or `sigyn run exec` to inject secrets
5. Clean up sensitive files

```bash
#!/bin/bash
set -euo pipefail

# Install
curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh
export PATH="$HOME/.sigyn/bin:$PATH"

# Restore identity from bundle
SIGYN_HOME="${SIGYN_HOME:-$HOME/.sigyn}"
mkdir -p "$SIGYN_HOME/identities"
BUNDLE_JSON=$(echo "$SIGYN_CI_BUNDLE" | base64 -d)
FINGERPRINT=$(echo "$BUNDLE_JSON" | jq -r '.fingerprint')
echo "$BUNDLE_JSON" | jq -r '.identity' | base64 -d > "$SIGYN_HOME/identities/${FINGERPRINT}.identity"
chmod 600 "$SIGYN_HOME/identities/${FINGERPRINT}.identity"
echo "$BUNDLE_JSON" | jq -r '.device_key' | base64 -d > "$SIGYN_HOME/.device_key"
chmod 400 "$SIGYN_HOME/.device_key"

# Clone vault
mkdir -p ~/.ssh
echo "$VAULT_SSH_KEY" > ~/.ssh/sigyn_vault_key
chmod 600 ~/.ssh/sigyn_vault_key
export GIT_SSH_COMMAND="ssh -i ~/.ssh/sigyn_vault_key -o StrictHostKeyChecking=yes"
# Add host keys for your git provider
ssh-keyscan -t ed25519,rsa github.com >> ~/.ssh/known_hosts 2>/dev/null
git clone "$VAULT_REPO" "$SIGYN_HOME/vaults/$VAULT_NAME"
rm -f ~/.ssh/sigyn_vault_key

# Export secrets and run your command
export SIGYN_PASSPHRASE="$SIGYN_PASSPHRASE"
sigyn run exec --vault "$VAULT_NAME" --env "$ENVIRONMENT" -- your-command-here

# Cleanup
rm -rf "$SIGYN_HOME/identities" "$SIGYN_HOME/.device_key" "$SIGYN_HOME/vaults" 2>/dev/null || true
```

## Security Best Practices

### Built-in protections

All official integrations (GitHub Action, GitLab CI template, and Bitbucket Pipe) include the following security hardening measures:

- **Input validation** — vault names and fingerprints are validated against strict patterns to prevent path traversal attacks
- **SSH host key verification** — uses `StrictHostKeyChecking=yes` with pre-fetched host keys for github.com and gitlab.com (no TOFU)
- **Automatic cleanup** — identity files, device keys, vault data, and SSH keys are removed from the runner after every run (even on failure)
- **Path restriction** — `dotenv-path` must be a relative path with no `..` components to prevent writing secrets to arbitrary locations
- **Stderr suppression** — `sigyn run export` stderr is suppressed to prevent leaking values before masking takes effect

### Pin to a specific version

Using `@main` or `latest` is convenient but means your pipeline tracks whatever is on the main branch. For production workflows, pin to a specific version:

```yaml
# GitHub Actions — pin to a commit SHA
- uses: tonybenoy/sigyn/action@<commit-sha>

# GitLab CI — pin to a tagged version
include:
  - remote: 'https://raw.githubusercontent.com/tonybenoy/sigyn/<commit-sha>/action/gitlab-ci-template.yml'

# Bitbucket Pipelines — pin to a versioned Docker tag
- pipe: docker://tonybenoy/sigyn-pipe:1.0.0
```

This protects against supply chain attacks where the integration code could change between your runs.

### Use a dedicated CI identity with minimal permissions

- Create a **separate identity** for CI — never reuse a human's personal identity
- Grant the **minimum role** needed (usually `reader`)
- Scope to **specific environments** (e.g., `--envs staging,prod` instead of all environments)
- Consider separate identities per deployment target (one for staging, one for prod)

```bash
sigyn identity create --name ci-staging
sigyn delegation invite create --role reader --envs staging

sigyn identity create --name ci-prod
sigyn delegation invite create --role reader --envs prod
```

### Use read-only deploy keys

The `vault-ssh-key` should be a **deploy key** with **read-only** access to the vault repository. Never use a personal SSH key or a key with write access unless your pipeline needs to push audit entries.

### Rotate CI credentials

Periodically rotate your CI identity and bundle:

```bash
# Revoke the old CI identity
sigyn delegation revoke <old-ci-fingerprint>

# Create a fresh one
sigyn identity create --name ci-bot-v2
sigyn delegation invite create --role reader --envs staging,prod
sigyn ci setup ci-bot-v2

# Update repository secrets with the new bundle and passphrase
```

### Mask secrets in logs

The action masks secret values by default (`mask: true`). Keep this enabled — it prevents accidental exposure in build logs. Note that GitHub Actions masking has limitations:

- Values shorter than 4 characters are **not masked** by GitHub
- Multiline values are masked line by line — each line is registered as a separate mask
- Structured output (JSON, YAML) may partially leak key names even when values are masked

### Limit secret scope with key filtering

Only export the secrets each step actually needs:

```yaml
# Only load database credentials for the migration step
- name: Load DB secrets
  uses: tonybenoy/sigyn/action@main
  with:
    # ...
    keys: "DATABASE_URL,DATABASE_POOL_SIZE"

- name: Run migrations
  run: ./migrate.sh
```

### Use GitHub Environments for approval gates

Combine Sigyn environments with [GitHub Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) for manual approval before production deployments:

```yaml
jobs:
  deploy-prod:
    runs-on: ubuntu-latest
    environment: production  # requires manual approval
    steps:
      - uses: tonybenoy/sigyn/action@main
        with:
          # ...
          environment: prod
```

## Troubleshooting

### "Permission denied (publickey)" when cloning vault

The SSH key cannot access the vault repository.

- Verify the `VAULT_SSH_KEY` secret contains the **private** key (it should have the standard OpenSSH PEM header)
- Ensure the corresponding **public** key is added as a deploy key on the vault repo
- Check that the deploy key has read access to the correct repository
- The key must not have a passphrase — generate with `ssh-keygen -t ed25519 -N ""`

### "Failed to decrypt identity" or "Invalid passphrase"

- Verify `SIGYN_PASSPHRASE` matches the passphrase set when the CI identity was created
- Ensure `SIGYN_CI_BUNDLE` hasn't been truncated — GitHub has a 48KB limit per secret
- Regenerate the bundle with `sigyn ci setup <identity-name>` if the identity or device key has changed

### "No such vault" or "Vault not found"

- The `vault` input must match the vault directory name inside the cloned repository
- Check that the vault repo URL is correct and the vault exists at the expected path
- If using a monorepo with multiple vaults, ensure the vault name matches the subdirectory

### "Access denied" for an environment

- The CI identity's delegation must include the requested environment
- Check with `sigyn delegation list` that the identity has access to the environment
- If the delegation was created with `--envs staging`, the identity cannot access `prod`

### Secrets not available in subsequent steps

- **GitHub Actions:** `env` mode writes to `$GITHUB_ENV`, which is only available in **subsequent** steps, not the same step
- **GitLab CI:** `env` mode uses dotenv artifact reports — downstream jobs must declare `needs:` to receive the variables
- **Bitbucket Pipelines:** Use `source .env` after the pipe step to load secrets into the current shell
- Verify the export step completed successfully (check for errors in the logs)
- Check the `count` output — if it's `0`, the environment may be empty or the key filter matched nothing

### Bundle encoding issues

The bundle is a base64-encoded JSON string. Common issues:

- **Copy/paste errors**: Use `sigyn ci setup --json` and pipe directly: `sigyn ci setup ci-bot | pbcopy`
- **Line breaks**: GitHub Secrets strip trailing newlines but preserve internal ones. The bundle should be a single line.
- **Re-encoding**: Do not base64-encode the bundle again when pasting into GitHub Secrets — it's already encoded

### Action version / install failures

- If `version: latest` fails to download, the install script may be unreachable. Pin a specific version as a fallback.
- All integrations require `curl`, `jq`, and `git` — pre-installed on most CI runner images
- Self-hosted runners or minimal Docker images may need these dependencies installed manually
