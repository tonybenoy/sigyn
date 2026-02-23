# Forks

Forks allow teams to create independent or semi-independent copies of a vault. This is useful for feature branches, team-specific configurations, or organizational splits.

## Fork Modes

### Leashed Fork

A leashed fork maintains a link to the parent vault. The upstream admin retains access to the fork and can audit or revoke access at any time.

```bash
sigyn fork create myapp-feature --mode leashed
```

Properties:
- Parent admin's key is always in the fork's member list
- Parent can audit the fork's operations
- Parent can revoke the fork
- Secrets can be synced back to the parent with approval
- Maximum drift (days since last sync) can be enforced

### Unleashed Fork

An unleashed fork is fully independent. A new master key is generated, and the parent vault has no access.

```bash
sigyn fork create myapp-independent --mode unleashed
```

Properties:
- Completely independent encryption (new master key)
- No upstream access or audit capability
- Cannot sync back to the parent
- Useful for permanent splits or when full autonomy is required

## Managing Forks

```bash
# List all forks of the current vault
sigyn fork list

# Check fork status (drift, sync state)
sigyn fork status myapp-feature

# Sync a leashed fork with its parent
sigyn fork sync myapp-feature

# Approve a fork sync request (as parent admin)
sigyn fork approve myapp-feature

# Set expiry on a fork
sigyn fork expire myapp-feature --days 30
```

## Fork Policy

Fork policies control:
- **Sharing policy**: Private (fork-only), SharedWithParent, or Public
- **Max drift days**: How long a leashed fork can go without syncing
- **Inherit revocations**: Whether parent revocations cascade to the fork
- **New member allowance**: Whether fork admins can add members independently
