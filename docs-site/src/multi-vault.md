# Working with Multiple Vaults, Projects, and Organizations

Sigyn supports managing secrets across multiple projects and organizations from
a single machine. Each vault is fully independent with its own master key,
members, policies, audit log, and git remote.

## Multiple Vaults

Create a separate vault for each project:

```bash
sigyn vault create webapp
sigyn vault create api-service
sigyn vault create infra
```

Each vault is stored in its own directory under `~/.sigyn/vaults/`:

```
~/.sigyn/vaults/
├── webapp/
├── api-service/
└── infra/
```

Use `--vault` to specify which vault a command operates on:

```bash
sigyn secret set DB_URL 'postgres://...' --vault webapp --env dev
sigyn secret set DB_URL 'postgres://...' --vault api-service --env dev
```

Or set a default vault to avoid repeating it:

```bash
sigyn init --vault webapp
sigyn secret set DB_URL 'postgres://...' --env dev   # uses webapp
```

List all vaults on this machine:

```bash
sigyn vault list
```

## Multiple Git Remotes

Each vault syncs to its own git remote independently. This means different
projects can live in different repositories, different GitHub organizations,
or different hosting providers entirely.

```bash
sigyn sync configure --vault webapp --remote-url git@github.com:acme/webapp-secrets.git
sigyn sync configure --vault api-service --remote-url git@github.com:acme/api-secrets.git
sigyn sync configure --vault infra --remote-url git@gitlab.com:acme/infra-secrets.git
```

Push and pull are per-vault:

```bash
sigyn sync push --vault webapp
sigyn sync pull --vault api-service
```

## Multiple Organizations

If you work for multiple organizations, you can use separate identities and
vaults for each. There is no shared state between vaults — each has its own
master key and member list.

```bash
# Identity for Acme Corp
sigyn identity create --name "alice-acme" --email alice@acme.com

# Identity for Globex Inc
sigyn identity create --name "alice-globex" --email alice@globex.com
```

Create vaults using the appropriate identity:

```bash
sigyn vault create acme-app --identity alice-acme
sigyn vault create globex-app --identity alice-globex
```

Each vault syncs to that organization's repository:

```bash
sigyn sync configure --vault acme-app --remote-url git@github.com:acme/secrets.git
sigyn sync configure --vault globex-app --remote-url git@github.com:globex/secrets.git
```

Access secrets with the matching identity:

```bash
sigyn secret get API_KEY --vault acme-app --identity alice-acme --env prod
sigyn secret get API_KEY --vault globex-app --identity alice-globex --env prod
```

## Switching Contexts

The `--vault` and `--identity` flags override the defaults set in
`~/.sigyn/config.toml` for a single command. To change your default context:

```bash
# Switch default vault
sigyn init --vault acme-app --identity alice-acme

# Later, switch to a different project
sigyn init --vault globex-app --identity alice-globex
```

The `sigyn status` command shows your current defaults:

```bash
sigyn status
```

## Isolation Guarantees

Each vault is cryptographically isolated:

- **Separate master keys.** Vault A's master key cannot decrypt vault B's secrets.
- **Separate member lists.** Being a member of vault A grants no access to vault B.
- **Separate audit logs.** Operations on vault A do not appear in vault B's audit trail.
- **Separate sync.** Pushing vault A does not affect vault B's git remote.
- **Separate policies.** RBAC roles, constraints, and delegation trees are per-vault.

An identity (keypair) can be a member of multiple vaults. The same X25519
public key is used to create a recipient slot in each vault's envelope header.
Compromising one vault's master key does not compromise other vaults, even
if they share members.

## Example: Full Multi-Org Setup

```bash
# Create identities
sigyn identity create --name "alice-acme" --email alice@acme.com
sigyn identity create --name "alice-globex" --email alice@globex.com

# Create vaults
sigyn vault create acme-web --identity alice-acme
sigyn vault create acme-api --identity alice-acme
sigyn vault create globex-platform --identity alice-globex

# Configure sync remotes
sigyn sync configure --vault acme-web --remote-url git@github.com:acme/web-secrets.git
sigyn sync configure --vault acme-api --remote-url git@github.com:acme/api-secrets.git
sigyn sync configure --vault globex-platform --remote-url git@github.com:globex/platform-secrets.git

# Add secrets to each
sigyn secret set DB_URL 'postgres://acme-web-db/...' --vault acme-web --env prod
sigyn secret set DB_URL 'postgres://acme-api-db/...' --vault acme-api --env prod
sigyn secret set DB_URL 'postgres://globex-db/...' --vault globex-platform --env prod

# Run applications with the right secrets
sigyn run exec --vault acme-web --env prod -- ./acme-web-server
sigyn run exec --vault globex-platform --env prod -- ./globex-app

# Sync each independently
sigyn sync push --vault acme-web
sigyn sync push --vault acme-api
sigyn sync push --vault globex-platform
```

## Related Documentation

- [Getting Started](getting-started.md) -- basic setup tutorial
- [CLI Reference](cli-reference.md) -- full command reference
- [Sync](sync.md) -- git sync and conflict resolution
- [Configuration](../docs-site/src/configuration.md) -- config file details
