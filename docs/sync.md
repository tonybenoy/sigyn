# Synchronization

This document describes how Sigyn synchronizes vault data between machines and
team members.

## Overview

Sigyn's sync system is designed around three principles:

1. **Encrypted at rest**: the sync engine operates on encrypted CBOR blobs. It never
   needs the master key. This means vault data can be stored in any git repository
   (including public ones) without exposing secrets.
2. **Conflict-aware**: concurrent modifications by different members are detected
   using vector clocks and resolved using configurable strategies.
3. **Git-native**: vaults are directories of files that can be committed, pushed,
   and pulled using standard git workflows.

## Git-Based Sync

Each vault is a directory under `~/.sigyn/vaults/<name>/` containing files that map
directly to git-trackable artifacts:

```
vaults/myapp/
  vault.toml        # Vault metadata
  members.cbor      # Encrypted envelope header
  policy.cbor       # Encrypted policy
  envs/
    dev.vault       # Encrypted environment
    staging.vault
    prod.vault
  audit.log.json    # Append-only audit trail
  forks.cbor        # Fork metadata
```

All `.cbor` and `.vault` files are encrypted. The sync engine pushes and pulls
these files without decrypting them.

### Configuration

Set up a remote for sync:

```bash
sigyn sync configure --remote git@github.com:team/secrets.git
```

### Push and Pull

```bash
# Push local changes to the remote repository
sigyn sync push

# Pull remote changes and merge locally
sigyn sync pull
```

The push/pull operations are wrappers around git operations (add, commit, push, pull)
that handle the vault directory structure and conflict detection.

### Status

Check what has changed locally and remotely:

```bash
sigyn sync status
```

Output shows:
- Local changes not yet pushed
- Remote changes not yet pulled
- Detected conflicts (if any)

## Vector Clocks

Sigyn uses vector clocks to track the causal ordering of modifications across
members. Each member maintains a logical clock, identified by their key fingerprint.

### Structure

```rust
pub struct VectorClock {
    pub clocks: HashMap<String, u64>,  // fingerprint_hex -> counter
}
```

### Operations

| Operation | Description |
|---|---|
| `tick(node_id)` | Increment this node's counter by 1 |
| `merge(other)` | Take the component-wise maximum of two clocks |
| `happened_before(other)` | Returns true if this clock causally precedes the other |
| `concurrent_with(other)` | Returns true if neither clock precedes the other |

### Causal Ordering

Given two vector clocks A and B:

- **A happened-before B**: every component of A is less than or equal to the
  corresponding component of B, and at least one is strictly less.
- **B happened-before A**: the reverse.
- **Concurrent**: neither happened-before the other (there exist components where
  A > B and components where B > A).

When two modifications are concurrent, a conflict is detected and must be resolved.

### Example

```
Alice writes DATABASE_URL:
  Clock: { alice: 1 }

Bob (who has seen Alice's write) writes API_KEY:
  Clock: { alice: 1, bob: 1 }

Alice (who has NOT seen Bob's write) writes API_KEY:
  Clock: { alice: 2 }

Result: Alice's { alice: 2 } and Bob's { alice: 1, bob: 1 } are concurrent.
  -> Conflict detected on API_KEY
```

## LWW-Map CRDT

Sigyn uses a Last-Write-Wins Map (LWW-Map) as its conflict-free replicated data type
for automatic convergence of non-conflicting changes.

### Structure

```rust
pub struct LwwMap<V> {
    pub entries: HashMap<String, LwwEntry<V>>,
}

pub struct LwwEntry<V> {
    pub value: V,
    pub timestamp: DateTime<Utc>,
    pub clock: VectorClock,
    pub writer: String,  // fingerprint of the writer
}
```

Each entry in the map tracks:
- The current value
- A UTC timestamp of when it was written
- The vector clock at the time of writing
- The fingerprint of the member who wrote it

### Merge Behavior

When merging two LWW-Maps (e.g., during `sigyn sync pull`):

1. For each key present in both maps, compare timestamps.
2. The entry with the later timestamp wins.
3. Keys present in only one map are added to the merged result.

This provides automatic convergence for the common case where different members
modify different keys. Conflicts (same key modified concurrently) are detected
by comparing vector clocks and escalated to the conflict resolution system.

## Conflict Detection

A conflict occurs when:

1. Two members modify the same key in the same environment.
2. Their vector clocks are concurrent (neither happened-before the other).

### Conflict Structure

```rust
pub struct Conflict {
    pub key: String,
    pub env: String,
    pub local_value: String,
    pub remote_value: String,
    pub local_clock: VectorClock,
    pub remote_clock: VectorClock,
}
```

## Conflict Resolution Strategies

Sigyn supports six conflict resolution strategies:

| Strategy | Description |
|---|---|
| `TakeLocal` | Keep the local value, discard the remote |
| `TakeRemote` | Keep the remote value, discard the local |
| `TakeLatestTimestamp` | Keep whichever value has the later UTC timestamp |
| `TakeHigherRole` | Keep the value written by the member with the higher role level |
| `Merge(custom)` | Use a custom merged value provided by the user |
| `Defer` | Leave the conflict unresolved for later manual resolution |

### Automatic Resolution

By default, `TakeLatestTimestamp` is used for automatic resolution during
`sigyn sync pull`. This can be configured:

```bash
sigyn sync configure --conflict-strategy take-latest
```

### Manual Resolution

When automatic resolution is not appropriate (or when using the `Defer` strategy),
conflicts must be resolved manually:

```bash
# List unresolved conflicts
sigyn sync status

# Resolve a specific conflict
sigyn sync resolve --key DATABASE_URL --env dev --strategy take-local

# Resolve with a custom value
sigyn sync resolve --key DATABASE_URL --env dev --strategy merge --value 'postgres://new-host/db'
```

## LAN Peer Discovery

For teams on the same network, Sigyn supports file-based peer advertising for
LAN discovery.

### How It Works

1. Each Sigyn instance advertises its presence by writing a peer file to a shared
   location (configurable).
2. The peer file contains: fingerprint, hostname, IP address, last-seen timestamp.
3. Other instances periodically scan for peer files.
4. Stale peer entries (not updated within a configurable window) are pruned automatically.

### Commands

```bash
# List discovered peers
sigyn sync peers

# Enable/disable LAN discovery
sigyn sync configure --lan-discovery on
```

## Sync Commands Reference

### sync push

Push local vault changes to the configured remote.

```bash
sigyn sync push
```

Options:
- `--force`: overwrite remote changes (use with caution)
- `--dry-run`: show what would be pushed without actually pushing

### sync pull

Pull and merge remote changes.

```bash
sigyn sync pull
```

Options:
- `--conflict-strategy <strategy>`: override the default conflict resolution strategy for this pull
- `--dry-run`: show what would change without applying

### sync status

Show the current sync state.

```bash
sigyn sync status
```

Displays:
- Number of local changes pending push
- Number of remote changes pending pull
- List of unresolved conflicts
- Last sync timestamp

### sync resolve

Manually resolve a conflict.

```bash
sigyn sync resolve --key <KEY> --env <ENV> --strategy <STRATEGY>
```

### sync peers

List known peers.

```bash
sigyn sync peers
```

### sync configure

Set sync configuration.

```bash
sigyn sync configure --remote <URL>
sigyn sync configure --conflict-strategy <STRATEGY>
sigyn sync configure --lan-discovery on|off
```

## Security Considerations

- **No plaintext in transit**: all synced files are encrypted CBOR blobs. The git
  remote (even if public) never sees plaintext secrets.
- **No master key needed for sync**: the sync engine only moves encrypted files.
  Decryption happens locally after pull.
- **Audit trail integrity**: the hash-chained audit log is synced alongside vault
  data. Chain verification (`sigyn audit verify`) detects tampering during transit.
- **Vector clocks prevent silent overwrites**: concurrent modifications are always
  detected and surfaced, never silently lost.

## Typical Workflow

```bash
# Morning: pull latest changes from the team
sigyn sync pull

# Work: make changes to secrets
sigyn secret set NEW_API_KEY 'sk-...' --env dev

# End of day: push changes
sigyn sync push

# If conflicts are reported during pull:
sigyn sync status
sigyn sync resolve --key API_KEY --env dev --strategy take-remote
sigyn sync push
```

## Related Documentation

- [Architecture](architecture.md) -- sync module structure and CRDT implementation
- [Security Model](security.md) -- encryption guarantees for synced data
- [CLI Reference](cli-reference.md) -- full sync command reference
- [Delegation](delegation.md) -- how delegation changes propagate via sync
