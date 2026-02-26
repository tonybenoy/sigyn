# Example Usage & Recipes

This page provides concrete examples for common Sigyn workflows.

## CI/CD Integration

### GitHub Actions

To use Sigyn in GitHub Actions, you can store your identity's private key and passphrase as GitHub Secrets, then use them to inject secrets into your build.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Sigyn
        run: cargo install sigyn-cli

      - name: Setup Identity
        run: |
          echo "${{ secrets.SIGYN_IDENTITY_KEY }}" > ~/.sigyn/identities/ci/identity.toml
          # The identity must be unlocked. For CI, consider using a non-passphrase protected
          # identity if the environment is secure, or use a tool like 'expect' to provide
          # the passphrase securely.

      - name: Run Tests with Secrets
        run: |
          sigyn run --staging -- ./scripts/run-tests.sh
```

### GitLab CI

```yaml
test:
  image: rust:latest
  script:
    - cargo install sigyn-cli
    - sigyn run -e dev -- npm test
```

## Advanced Process Injection

### Using with Docker

Injecting secrets into a Docker container without ever writing them to a `.env` file:

```bash
sigyn run exec --env prod -- docker run --env-file <(sigyn run export --format docker) my-app:latest
```

Or more simply if you want all Sigyn secrets to be env vars in the container:

```bash
sigyn run exec --env prod -- docker run my-app:latest
```

### Shell Alias for Development

Add this to your `.bashrc` or `.zshrc` to always run your local dev server with Sigyn secrets:

```bash
alias dev='sigyn run -e dev -- npm run dev'
```

Or better yet, use a `.sigyn.toml` project config with named commands:

```toml
# .sigyn.toml
[project]
vault = "myapp"
env = "dev"

[commands]
dev = "npm run dev"
```

Then just run `sigyn run dev` -- no alias needed.

## Team Onboarding and Offboarding

### Onboarding a New Team Member

**Step 1 — New member creates their identity:**

```bash
# Bob runs this on his machine
sigyn identity create --name bob --email bob@example.com
sigyn identity export --name bob > bob.pub
# Send bob.pub to the team lead (Alice) via a secure channel
```

**Step 2 — Team lead creates a scoped invitation:**

```bash
# Alice imports Bob's public key and creates an invitation
sigyn identity import bob.pub

sigyn delegation invite create \
  --role contributor \
  --envs dev,staging \
  --patterns '*'
# Produces invitation-<id>.json — send it to Bob
```

**Step 3 — New member accepts and verifies access:**

```bash
# Bob accepts the invitation
sigyn delegation invite accept ./invitation-abc123.json

# Pull the vault to get encrypted secrets
sigyn sync pull

# Verify access works
sigyn policy check $(sigyn identity show bob --json | jq -r .fingerprint) read --env dev
#   Result: ALLOW

sigyn policy check $(sigyn identity show bob --json | jq -r .fingerprint) write --env prod
#   Result: DENY (not in allowed envs)
```

### Offboarding a Team Member

When someone leaves the team, revoke their access and clean up the delegation tree.

**Step 1 — Inspect the delegation tree to understand impact:**

```bash
sigyn delegation tree
# alice (a1b2c3d4...) [owner]
#   bob (e5f6a7b8...) [contributor]
#     carol (c9d0e1f2...) [readonly]    <-- Bob invited Carol
#   dave (a3b4c5d6...) [admin]
```

**Step 2 — Revoke with cascade (removes Bob and everyone Bob invited):**

```bash
sigyn delegation revoke e5f6a7b8... --cascade
# Revoked: bob (e5f6a7b8...), carol (c9d0e1f2...)
# Master key rotated.
```

**Step 3 — Push changes and rotate high-value secrets:**

```bash
sigyn sync push

# Rotate any secrets Bob had access to
sigyn rotate key DB_PASSWORD --env dev
sigyn rotate key DB_PASSWORD --env staging
sigyn rotate key API_KEY --env dev
sigyn rotate key API_KEY --env staging
```

If Carol should keep access, re-invite her directly before revoking Bob,
or use `sigyn delegation revoke e5f6a7b8...` (without `--cascade`) and
manually reassign Carol's delegation.

## Contractor and Temporary Access

### Granting Time-Limited Access

Create a time-limited invitation with scoped permissions for a contractor:

```bash
sigyn delegation invite create \
  --role contributor \
  --envs dev \
  --patterns "STRIPE_*,PAYMENT_*" \
  --expires 90d
# Produces invitation-<id>.json — send to the contractor
```

The invitation (and resulting access) expires automatically after 90 days.

### Verifying Contractor Constraints

After the contractor accepts, verify what they can and cannot do:

```bash
# Allowed: read payment secrets in dev
sigyn policy check <contractor-fp> read --env dev --key STRIPE_SECRET_KEY
#   Result: ALLOW

# Denied: access production
sigyn policy check <contractor-fp> read --env prod --key STRIPE_SECRET_KEY
#   Result: DENY (env not allowed)

# Denied: access secrets outside their pattern
sigyn policy check <contractor-fp> read --env dev --key DATABASE_URL
#   Result: DENY (key does not match allowed patterns)
```

### Cleanup

When the contract ends, either wait for auto-expiry or revoke explicitly:

```bash
sigyn delegation revoke <contractor-fp>
sigyn sync push
```

## Complex Policies

### Restricting a Member to Specific Keys

Add a member who can only see database-related secrets in the `staging` environment:

```bash
sigyn policy member-add <fingerprint>
  --role readonly
  --envs staging
  --patterns "DB_*,POSTGRES_*"
```

### Implementing a "Break Glass" Auditor

An auditor who can see everything but only in an emergency (monitored via audit logs):

```bash
sigyn policy member-add <fingerprint>
  --role auditor
  --envs '*'
  --patterns '*'
```

## MFA Enforcement

### Requiring MFA for All Members

Enable MFA globally by setting `require_mfa: true` in the vault's global constraints.
Every non-owner member will be prompted for a TOTP code on their first access (then
a 1-hour session grace period kicks in).

First, have each team member enroll:

```bash
sigyn mfa setup -i alice
```

Then set the policy constraint (as vault owner):

```bash
# In the vault policy, set global_constraints.require_mfa = true
sigyn policy show --vault myapp   # verify current policy
```

### MFA for Specific Members

You can also require MFA only for certain members by setting `require_mfa: true` on
their individual member constraints rather than globally. This is useful for
restricting high-privilege roles while leaving read-only members unaffected.

### Generating New Backup Codes

If a team member loses their backup codes, they can generate a fresh set (the old
codes are immediately invalidated):

```bash
sigyn mfa backup -i alice
```

## Secret Rotation

### Manual Rotation of a Database Password

1. Rotate the secret in Sigyn:
   ```bash
   sigyn rotate key DB_PASSWORD --env prod
   ```
2. Export the new value to update your cloud provider (e.g., AWS RDS):
   ```bash
   NEW_PASS=$(sigyn secret get DB_PASSWORD --env prod)
   aws rds modify-db-instance --db-instance-identifier mydb --master-user-password "$NEW_PASS"
   ```

## Rotation Schedules with Hooks

### Automated Database Password Rotation

Create a hook script that updates AWS RDS after Sigyn rotates the secret:

```bash
#!/usr/bin/env bash
# hooks/rotate-db.sh — called after sigyn rotates DB_PASSWORD
set -euo pipefail

NEW_PASS=$(sigyn secret get DB_PASSWORD --env prod)
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --master-user-password "$NEW_PASS"

echo "RDS password updated successfully"
```

Set a weekly rotation schedule with the hook:

```bash
sigyn rotate schedule set -v myapp \
  --key DB_PASSWORD \
  --cron "0 0 * * MON" \
  --grace-hours 48 \
  --hooks hooks/rotate-db.sh
```

Verify the schedule is active:

```bash
sigyn rotate schedule list -v myapp
# KEY            CRON             GRACE  HOOKS              NEXT RUN
# DB_PASSWORD    0 0 * * MON     48h    rotate-db.sh       2026-03-02 00:00 UTC
```

Test it manually to make sure the hook works end-to-end:

```bash
sigyn rotate key DB_PASSWORD --env prod
```

### Monthly Redis Auth Token Rotation

```bash
#!/usr/bin/env bash
# hooks/rotate-redis.sh
set -euo pipefail

NEW_TOKEN=$(sigyn secret get REDIS_AUTH_TOKEN --env prod)
redis-cli -h redis.internal CONFIG SET requirepass "$NEW_TOKEN"
echo "Redis auth token updated"
```

```bash
sigyn rotate schedule set -v myapp \
  --key REDIS_AUTH_TOKEN \
  --cron "0 2 1 * *" \
  --grace-hours 24 \
  --hooks hooks/rotate-redis.sh
```

## First-Time Setup

### Using the Onboard Wizard

The fastest way to get started is the guided wizard:

```bash
sigyn onboard
```

This walks you through:
1. Creating an identity (if none exists)
2. Creating a vault (auto-detects project name)
3. Importing `.env` files found in the current directory
4. Setting up `.sigyn.toml`

In CI or non-interactive environments, it prints a checklist instead:

```bash
sigyn onboard
# Sigyn Setup Checklist
# ─────────────────────────────────
#   ✓ Identity created
#   ✗ Vault created
#     → sigyn vault create <name>
#   ✗ Project config (.sigyn.toml)
#     → sigyn project init
```

### Smarter Init

`sigyn init` now offers to create missing identity and vault interactively:

```bash
sigyn init
# No identities found. Create one now? [Y/n]
# Identity name: alice
# ...
# No vaults found. Create one now? [Y/n]
# Vault name: myapp (detected from Cargo.toml)
# ...
# ✓ Configuration initialized
```

## Environment Comparison and Cloning

### Comparing Environments

Before promoting, check what differs between environments:

```bash
# Summary of differences (values hidden)
sigyn env diff dev staging
#   - OLD_DEBUG_KEY (removed)
#   + NEW_STAGING_KEY (added)
#   ~ DATABASE_URL (changed)

# See actual values
sigyn env diff dev staging --reveal

# Machine-readable output
sigyn env diff dev prod --json
```

### Cloning an Environment

Quickly create a copy of an environment for testing:

```bash
sigyn env clone dev qa
# ✓ Cloned 'dev' → 'qa' (12 secrets)

# Now customize the QA-specific values
sigyn secret set DATABASE_URL "postgres://qa-db/myapp" --env qa
```

## Batch Editing and Cross-Environment Search

### Editing Secrets in Your Editor

Open all secrets in an environment for bulk editing:

```bash
sigyn secret edit --env dev
# Opens $EDITOR with:
#   DATABASE_URL=postgres://localhost/myapp
#   API_KEY=sk-abc123
#   FEATURE_FLAG=true
#
# Make changes, save, close. Sigyn shows a diff and confirms.
```

### Searching Across Environments

Find secrets matching a pattern across all environments in a vault:

```bash
# Find all database-related secrets
sigyn secret search 'DB_*'
#   [dev] DB_HOST = ••••••••
#   [dev] DB_PORT = ••••••••
#   [staging] DB_HOST = ••••••••
#   [prod] DB_HOST = ••••••••

# Show actual values
sigyn secret search 'API_*' --reveal
```

## Webhook Notifications

### Setting Up Notifications

Configure a webhook to get notified when secrets change:

```bash
sigyn notification configure
# Webhook URL: https://hooks.slack.com/services/T.../B.../xxx
# Select events: * (all events)
# Shared secret: (optional)
# ✓ Webhook configured
```

### Testing Notifications

Send a test event to verify your webhook works:

```bash
sigyn notification test
#   ✓ https://hooks.slack.com/services/T.../B.../xxx
# ✓ Test sent to 1 webhook(s)
```

### Listing Configured Webhooks

```bash
sigyn notification list
# Configured Webhooks
# ────────────────────────────────────────────────────────────
#   1. https://hooks.slack.com/services/T.../B.../xxx
#      Events: *
```

## Auto-Sync

Enable auto-sync to automatically push changes after every write:

```bash
sigyn sync configure --auto-sync true

# Now every secret set/remove/generate automatically pushes
sigyn secret set API_KEY "new-value" --env dev
# ✓ Set 'API_KEY' in env 'dev'
# note: auto-syncing...
```

## Environment Promotion Workflow

### Promoting Secrets Through the Pipeline

A typical workflow: set secrets in dev, then promote through staging to production.

**Step 1 — Set secrets in dev:**

```bash
sigyn secret set API_KEY "dev-key-abc123" --env dev
sigyn secret set DATABASE_URL "postgres://localhost/myapp_dev" --env dev
sigyn secret set FEATURE_FLAG "true" --env dev
```

**Step 2 — Promote all secrets from dev to staging:**

```bash
# Preview what will change first
sigyn env promote --from dev --to staging --dry-run
# Would promote: API_KEY, DATABASE_URL, FEATURE_FLAG
# Would overwrite: (none)

# Apply the promotion
sigyn env promote --from dev --to staging
```

**Step 3 — Override staging-specific values:**

```bash
sigyn secret set DATABASE_URL "postgres://staging-db.internal/myapp" --env staging
```

**Step 4 — Selectively promote to production:**

```bash
# Only promote specific keys (not DATABASE_URL, which differs per environment)
sigyn env promote --from staging --to prod --keys API_KEY,FEATURE_FLAG

# Production DATABASE_URL is managed separately
sigyn secret set DATABASE_URL "postgres://prod-db.internal/myapp" --env prod
```

### Adding a QA Environment

```bash
# Option 1: Clone dev (copies all secrets in one step)
sigyn env clone dev qa

# Option 2: Create empty and promote selectively
sigyn env create qa
sigyn env promote --from dev --to qa

# Either way, QA team can now work with a snapshot of dev secrets
```

## Multi-Project Organization

### Scenario

You have one organization with multiple projects — say 3 backend services and 1
frontend app — each with their own environments and secrets. You want centralized
access control, minimal GitHub repos for sync, and per-project `.sigyn.toml` configs
so developers just `cd` into a repo and go.

### 1. Set up the org hierarchy

```bash
sigyn org create acme
sigyn org node create backend  --parent acme --type division
sigyn org node create frontend --parent acme --type division
```

This gives you:

```
acme (org)
├── backend (division)
└── frontend (division)
```

### 2. Create a vault per project, linked to the org

```bash
sigyn vault create api-service    --org acme/backend
sigyn vault create auth-service   --org acme/backend
sigyn vault create worker-service --org acme/backend
sigyn vault create dashboard      --org acme/frontend
```

Each vault has independent environments (`dev`, `staging`, `prod`), secrets, and
member lists — but inherits org-level policies and git remote configuration.

### 3. Configure git sync once at the org level

```bash
sigyn org sync configure --path acme \
  --remote-url git@github.com:acme-corp/secrets.git
```

All 4 vaults inherit this single remote. If the frontend team later needs a
separate repo, override at the child level:

```bash
sigyn org sync configure --path acme/frontend \
  --remote-url git@github.com:acme-corp/frontend-secrets.git
```

Now `acme/backend` still inherits the org remote, while `acme/frontend` uses its own.

### 4. Add a `.sigyn.toml` to each project repo

In `api-service/`:

```toml
[project]
vault = "api-service"
env = "dev"
identity = "alice"

[commands]
dev = "cargo run"
migrate = "sqlx migrate run"
```

In `dashboard/`:

```toml
[project]
vault = "dashboard"
env = "dev"
identity = "alice"

[commands]
dev = "npm run dev"
build = "npm run build"
```

### 5. Day-to-day usage

```bash
# In api-service/ — secrets come from the api-service vault, dev env
sigyn secret set DATABASE_URL "postgres://localhost/api"
sigyn run dev

# In dashboard/ — secrets come from the dashboard vault, dev env
sigyn secret set VITE_API_URL "http://localhost:8080"
sigyn run dev

# Switch to staging for a deploy
sigyn run exec --env staging -- ./deploy.sh
```

### 6. Team access control

Add an org-wide admin who can access all vaults:

```bash
sigyn org policy member-add <bob-fp> --role admin --path acme
```

Add a frontend contractor who can only access dashboard secrets in dev:

```bash
sigyn org policy member-add <carol-fp> --role contributor \
  --path acme/frontend --envs dev
```

Check effective permissions:

```bash
sigyn org policy effective <carol-fp> --path acme/frontend
#   Role: Contributor
#   Envs: dev
#   Patterns: *
```

### 7. Sync everything

```bash
sigyn sync push --vault api-service
sigyn sync push --vault auth-service
sigyn sync push --vault worker-service
sigyn sync push --vault dashboard
```

### Why this works

- **One or two GitHub repos** instead of one per vault — git remote inheritance
  means you set it once at the org level.
- **Per-project isolation** — each vault has its own master key, so compromising
  one doesn't affect the others.
- **Per-project `.sigyn.toml`** — developers just `cd` into a repo and `sigyn run dev`
  picks up the right vault, env, and identity automatically.
- **Cascading RBAC** — add someone at `acme` and they get access everywhere; add
  them at `acme/frontend` and they only see frontend vaults.
- **Independent environments** — `api-service` can be on `staging` while `dashboard`
  is still on `dev`.

## Monorepo with Shared Secrets

### Scenario

You have a monorepo with 3 services (API, worker, web frontend) that share some
infrastructure secrets (database URL, Redis URL) but also have service-specific
secrets (API keys, signing tokens). You want each service to see only what it needs
while avoiding duplication of shared values.

### 1. Create the vaults

```bash
sigyn vault create shared-infra     # DATABASE_URL, REDIS_URL, etc.
sigyn vault create api-service      # API-specific: STRIPE_KEY, JWT_SECRET
sigyn vault create worker-service   # Worker-specific: QUEUE_URL, DEAD_LETTER_ARN
sigyn vault create web-frontend     # Frontend-specific: NEXT_PUBLIC_API_URL
```

### 2. Populate shared and per-service secrets

```bash
# Shared infrastructure secrets
sigyn secret set DATABASE_URL "postgres://db.internal/myapp" -v shared-infra -e prod
sigyn secret set REDIS_URL "redis://redis.internal:6379" -v shared-infra -e prod

# API-specific
sigyn secret set STRIPE_SECRET_KEY "sk_live_..." -v api-service -e prod
sigyn secret set JWT_SECRET "..." -v api-service -e prod

# Worker-specific
sigyn secret set QUEUE_URL "https://sqs.us-east-1.amazonaws.com/..." -v worker-service -e prod
sigyn secret set DEAD_LETTER_ARN "arn:aws:sqs:..." -v worker-service -e prod

# Frontend-specific
sigyn secret set NEXT_PUBLIC_API_URL "https://api.example.com" -v web-frontend -e prod
```

### 3. Per-directory `.sigyn.toml` files

In `services/api/.sigyn.toml`:

```toml
[project]
vault = "api-service"
env = "dev"

[commands]
dev = "cargo run"
```

In `services/worker/.sigyn.toml`:

```toml
[project]
vault = "worker-service"
env = "dev"

[commands]
dev = "cargo run"
```

In `services/web/.sigyn.toml`:

```toml
[project]
vault = "web-frontend"
env = "dev"

[commands]
dev = "npm run dev"
```

### 4. Compose shared + service secrets at runtime

Use `sigyn run export` to merge secrets from multiple vaults:

```bash
# In services/api/ — load shared infra secrets, then layer on API-specific ones
eval $(sigyn run export -v shared-infra --env prod --format shell)
exec sigyn run exec --env prod -- ./api-server
```

Or in a wrapper script (`services/api/start.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# Export shared secrets into the environment
eval $(sigyn run export -v shared-infra --env "${SIGYN_ENV:-dev}" --format shell)

# Run with service-specific secrets layered on top
sigyn run exec --env "${SIGYN_ENV:-dev}" -- "$@"
```

```bash
# Usage
cd services/api && ./start.sh cargo run
```

## Emergency Breach Response

### Full Breach — All Secrets Compromised

If you suspect a broad compromise (e.g., vault key leaked), use breach mode
to rotate everything and revoke all delegated members in one step.

**Step 1 — Activate breach mode:**

```bash
sigyn rotate breach-mode --force
# All secrets rotated across all environments.
# All delegated members revoked.
# Master key rotated.
```

**Step 2 — Push the rotated vault:**

```bash
sigyn sync push
```

**Step 3 — Verify the delegation tree is clean:**

```bash
sigyn delegation tree
# alice (a1b2c3d4...) [owner]
#   (no delegated members)
```

**Step 4 — Update external systems with new secret values:**

```bash
# Update RDS
NEW_DB_PASS=$(sigyn secret get DB_PASSWORD --env prod)
aws rds modify-db-instance --db-instance-identifier mydb --master-user-password "$NEW_DB_PASS"

# Update Redis
NEW_REDIS_TOKEN=$(sigyn secret get REDIS_AUTH_TOKEN --env prod)
redis-cli -h redis.internal CONFIG SET requirepass "$NEW_REDIS_TOKEN"

# Repeat for all external integrations...
```

**Step 5 — Re-onboard trusted team members:**

```bash
# Create new invitations for each trusted member
sigyn delegation invite create --role admin --envs '*'
sigyn delegation invite create --role contributor --envs dev,staging
# Send invitations via a verified secure channel
```

**Step 6 — Audit, verify, and witness:**

```bash
# Export the audit log for incident documentation
sigyn audit export --output incident-audit.json --format json

# Verify the audit chain is intact
sigyn audit verify

# Have a second team member countersign the recovery
sigyn audit witness
```

### Targeted Response — Single Member Compromise

If only one member's key was compromised (e.g., stolen laptop), you can
scope the response to just that member:

```bash
# Revoke the compromised member and their delegates
sigyn delegation revoke <compromised-fp> --cascade
sigyn sync push

# Rotate only the secrets that member had access to
sigyn rotate key DB_PASSWORD --env dev
sigyn rotate key DB_PASSWORD --env staging
sigyn rotate key API_KEY --env dev

# Monitor for suspicious activity
sigyn audit tail -n 100
sigyn audit query --actor <compromised-fp>
```

## Disaster Recovery

### Creating Paper Backups

1. Create 5 shards, requiring 3 to recover:
   ```bash
   sigyn-recovery split --identity alice --threshold 3 --total 5 --output ./shards
   ```
2. Print them (or generate QR codes) to store in physical safes:
   ```bash
   sigyn-recovery print-shards ./shards/*.json
   ```

### Recovering a Vault

If Alice loses her laptop, she can reconstruct her identity on a new machine:

```bash
sigyn-recovery restore shard1.json shard2.json shard3.json --output recovered_identity.toml
sigyn identity import recovered_identity.toml
```

## Auditing and Compliance

### Verifying Audit Chain Integrity

Before any compliance review, verify the hash chain has not been tampered with:

```bash
sigyn audit verify
# Audit chain OK: 1,247 entries verified, no breaks detected.
```

### Querying Access Patterns

Search the audit log for specific access patterns:

```bash
# All production access events
sigyn audit query --env prod

# All actions by a specific member
sigyn audit query --actor a1b2c3d4...

# Combine filters
sigyn audit query --actor a1b2c3d4... --env prod
```

### Exporting for Compliance

Export the full audit trail for external compliance tools or auditors:

```bash
# JSON for programmatic analysis
sigyn audit export --output audit-q1-2026.json --format json

# CSV for spreadsheet review
sigyn audit export --output audit-q1-2026.csv --format csv
```

### Witness Countersigning

After sensitive operations (rotation, member changes, breach response),
have a second team member countersign the audit entry:

```bash
# After a rotation or breach response, the second admin runs:
sigyn audit witness
# Countersigned entry #1247 with fingerprint e5f6a7b8...
```

### Git Anchoring

Anchor the audit trail to a git commit for external tamper-evidence:

```bash
sigyn audit anchor -v myapp
# Anchored audit hash abc123... to git commit def456...
```

### Periodic Compliance Script

Automate weekly compliance checks with a cron job:

```bash
#!/usr/bin/env bash
# compliance-check.sh — run weekly via cron
set -euo pipefail

echo "=== Sigyn Compliance Check $(date -I) ==="

# Verify audit chain integrity
sigyn audit verify

# Check for secrets due for rotation
sigyn rotate due --env prod --max-age 90

# Export audit log for the past week
sigyn audit export --output "/var/log/sigyn/audit-$(date -I).json" --format json

# Anchor to git
sigyn audit anchor -v myapp

echo "=== Compliance check complete ==="
```

```cron
0 6 * * MON /opt/scripts/compliance-check.sh >> /var/log/sigyn/compliance.log 2>&1
```

## Scripting with Sigyn

### Bulk Update from a CSV

```bash
while IFS=, read -r key value; do
  sigyn secret set "$key" "$value" --env dev
done < secrets.csv
```

### Checking for Expiring Secrets

Find secrets that haven't been rotated in 6 months:

```bash
sigyn rotate due --env prod --max-age 180
```
