# Environments

Sigyn organizes secrets by environment. Common environments include `dev`, `staging`, and `prod`, but you can create any name.

## Creating Environments

```bash
sigyn env create dev
sigyn env create staging
sigyn env create prod
```

Each environment is stored as a separate encrypted file (`envs/<name>.vault`), encrypted with its own independent 256-bit key. Members only receive decryption keys for environments they are authorized to access, providing **cryptographic isolation** between environments -- not just policy-level separation.

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

## Cryptographic Isolation

Each environment has its own independent encryption key. When a member is granted access to specific environments (e.g., `--env dev,staging`), they receive key slots only for those environments. They physically cannot decrypt environments they are not authorized for.

This means:

- A Contributor with `allowed_envs: ["dev"]` cannot decrypt `prod` secrets, even with direct access to the encrypted files on disk.
- Revoking a member only rotates keys for environments they had access to -- unaffected environments are untouched.
- Granting or revoking access to individual environments is supported without affecting other environments:

```bash
# Grant access to an additional environment
sigyn delegation grant-env <fingerprint> staging

# Revoke access to a specific environment (rotates that env's key)
sigyn delegation revoke-env <fingerprint> staging
```

See [Security Model](security.md) for details on the envelope encryption scheme.
