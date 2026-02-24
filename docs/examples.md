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
