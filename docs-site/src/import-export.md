# Import and Export

Sigyn can import secrets from several sources and export to multiple formats.

## Import

### From .env Files

```bash
sigyn import dotenv .env --env dev
sigyn import dotenv .env.production --env prod
```

### From JSON

```bash
sigyn import json secrets.json --env dev
```

The JSON file should be a flat object with string values:

```json
{
  "DATABASE_URL": "postgres://...",
  "API_KEY": "sk-..."
}
```

### From Doppler

```bash
sigyn import doppler --project myapp --config dev --env dev
```

Requires the Doppler CLI to be installed and authenticated. Sigyn calls `doppler secrets download` and parses the output.

### From AWS Secrets Manager

```bash
sigyn import aws --secret-id myapp/dev --env dev --region us-east-1
```

Requires the AWS CLI to be installed and configured. Supports both key/value and plain string secrets.

### From GCP Secret Manager

```bash
sigyn import gcp --secret myapp-config --env dev --project my-gcp-project
```

Requires the `gcloud` CLI to be installed and authenticated.

### From 1Password

```bash
sigyn import 1password --item "MyApp Secrets" --vault "Engineering" --env dev
```

Requires the 1Password CLI (`op`) to be installed and authenticated. Imports all fields from the specified item.

## Export

Export secrets to various formats for use in deployment pipelines or local development.

```bash
# .env format
sigyn run export --env dev --format dotenv > .env

# JSON
sigyn run export --env dev --format json > secrets.json

# Kubernetes Secret manifest
sigyn run export --env prod --format k8s > k8s-secret.yaml

# Docker --env-file format
sigyn run export --env dev --format docker > docker.env

# Shell eval (export statements)
sigyn run export --env dev --format shell
eval "$(sigyn run export --env dev --format shell)"
```

## Process Injection

The recommended way to use secrets in applications is process injection. Secrets are passed as environment variables to a child process and never written to disk:

```bash
sigyn run exec --env dev -- ./myapp
sigyn run exec --env prod -- docker compose up
```

## Unix Socket Server

For programmatic access, Sigyn can serve secrets over a Unix domain socket:

```bash
sigyn run serve --env dev --socket ~/.sigyn/sigyn.sock
```

Clients connect and use a simple text protocol:

- `LIST` — returns all secret keys
- `GET <key>` — returns the value for a key
- `QUIT` — closes the connection
