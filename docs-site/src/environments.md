# Environments

Sigyn organizes secrets by environment. Common environments include `dev`, `staging`, and `prod`, but you can create any name.

## Creating Environments

```bash
sigyn env create dev
sigyn env create staging
sigyn env create prod
```

Each environment is stored as a separate encrypted file (`envs/<name>.vault`), so members can be granted access to specific environments without exposing others.

## Listing Environments

```bash
sigyn env list
```

## Setting Secrets Per Environment

```bash
sigyn secret set DATABASE_URL 'postgres://localhost/myapp' --env dev
sigyn secret set DATABASE_URL 'postgres://staging-host/myapp' --env staging
sigyn secret set DATABASE_URL 'postgres://prod-host/myapp' --env prod
```

## Promoting Secrets

Promotion copies secrets from one environment to another. This is useful when a configuration has been validated in staging and is ready for production.

```bash
# Promote all secrets from dev to staging
sigyn env promote --from dev --to staging

# Promote specific keys only
sigyn env promote --from staging --to prod --keys DATABASE_URL,API_KEY
```

Promotion records are logged in the audit trail.

## Environment Policies

Environments can have role-based restrictions. For example, you can require the `Admin` role to write to `prod` while allowing `Contributor` access to `dev` and `staging`. These are configured through the policy engine:

```bash
sigyn policy member add <fingerprint> --role contributor --env dev,staging
```

Members with access to an environment can read and write secrets within that environment, subject to their role and any additional constraints (time windows, IP allowlists, expiry).
