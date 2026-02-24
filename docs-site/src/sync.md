# Sync

This document describes how Sigyn synchronizes vault data between machines, including
the git-based transport, conflict detection via vector clocks, and CRDT-based resolution.

## Design Principles

- **Encrypted at rest**: the sync engine operates on encrypted CBOR blobs. It never
  needs the master key. A git remote (or any file synchronization tool) can host
  Sigyn vaults without having access to the plaintext secrets.
- **Vaults are directories**: each vault is a self-contained directory containing
  `vault.toml`, `members.cbor`, `policy.cbor`, `envs/*.vault`, `audit.log.json`,
  and `forks.cbor`. This maps naturally to git repositories.
- **No central server**: Sigyn is peer-to-peer. Any member can push/pull to a shared
  git remote.

## On-Disk Layout

The files synced for each vault:

```
~/.sigyn/vaults/myapp/
  vault.toml        # Vault metadata (TOML, human-readable)
  members.cbor      # Envelope header with encrypted master key slots
  policy.cbor       # Encrypted RBAC policy
  envs/
    dev.vault       # Encrypted environment (CBOR)
    staging.vault
    prod.vault
  audit.log.json    # Hash-chained audit trail (JSON Lines)
  forks.cbor        # Fork metadata
```

All `.cbor` and `.vault` files are encrypted with ChaCha20-Poly1305. The sync engine
pushes and pulls these opaque blobs without any decryption.

## Git-Based Sync

Sigyn uses `git2` (libgit2 Rust bindings) for sync operations. Each vault directory
can be initialized as a git repository via `GitSyncEngine`.

### GitSyncEngine

The engine operates on the vault directory:

```rust
GitSyncEngine {
    vault_path: PathBuf,
}
```

Key methods:

| Method | Description |
|---|---|
| `init()` | Initialize a git repository in the vault directory |
| `stage_all()` | Stage all changed files (`git add *`) |
| `commit(message)` | Create a commit with staged changes |
| `push(remote, branch)` | Push to a remote (`refs/heads/branch`) |
| `pull(remote, branch)` | Fetch and fast-forward merge |
| `sync(remote, branch, message)` | Pull, stage, commit, push in one operation |
| `has_changes()` | Check for uncommitted changes |
| `status()` | Compute sync status relative to remote |

### Sync Status

The engine computes sync status by comparing local HEAD with `refs/remotes/origin/main`:

| Status | Meaning |
|---|---|
| `NeverSynced` | No remote configured or no commits yet |
| `UpToDate` | Local and remote are at the same commit |
| `LocalAhead(n)` | Local has n commits not yet pushed |
| `RemoteAhead(n)` | Remote has n commits not yet pulled |
| `Diverged` | Both local and remote have new commits |

### Pull Results

A pull operation can result in:

| Result | Meaning |
|---|---|
| `UpToDate` | Nothing to pull |
| `FastForward` | Remote changes applied cleanly |
| `Conflict` | Diverged histories; needs resolution |

### Commands

```bash
# Configure a remote
sigyn sync configure --remote-url git@github.com:team/secrets.git

# Push local changes
sigyn sync push
sigyn sync push --remote origin --branch main

# Pull remote changes
sigyn sync pull
sigyn sync pull --remote origin --branch main

# Check status
sigyn sync status

# Enable auto-sync
sigyn sync configure --auto-sync true
```

## Vector Clocks

Sigyn uses vector clocks to track causal ordering of secret updates across nodes.
Each node is identified by its BLAKE3 key fingerprint.

### Structure

```rust
VectorClock {
    clocks: HashMap<String, u64>,  // fingerprint_hex -> counter
}
```

### Operations

| Operation | Description |
|---|---|
| `tick(node_id)` | Increment this node's counter by 1 |
| `merge(other)` | Take the component-wise maximum of two clocks |
| `happened_before(other)` | True if this clock causally precedes the other |
| `concurrent_with(other)` | True if neither clock precedes the other (conflict) |

### Causal Ordering

Given two vector clocks A and B:

- **A happened-before B**: every component of A is less than or equal to the
  corresponding component of B, and at least one is strictly less.
- **B happened-before A**: the reverse.
- **Concurrent**: neither happened-before the other. This indicates a conflict --
  two members modified the same key independently.

### Example

```
Alice writes DATABASE_URL:
  Clock: { alice: 1 }

Bob (who has seen Alice's write) writes API_KEY:
  Clock: { alice: 1, bob: 1 }

Alice (who has NOT seen Bob's write) writes API_KEY:
  Clock: { alice: 2 }

Alice's { alice: 2 } and Bob's { alice: 1, bob: 1 } are concurrent.
  -> Conflict detected on API_KEY.
```

After sync, the clocks are merged:

```
Merged: { alice: 2, bob: 1 }
```

## LWW-Map CRDT

For automatic conflict resolution, Sigyn uses a Last-Writer-Wins Map (LWW-Map). Each
entry in the map tracks metadata alongside the value:

```rust
LwwEntry<V> {
    value: V,                           // The secret value (encrypted)
    timestamp: DateTime<Utc>,            // When it was written
    clock: VectorClock,                  // Causal ordering
    writer: String,                      // Fingerprint of the writer
}

LwwMap<V> {
    entries: HashMap<String, LwwEntry<V>>,
}
```

### Merge Semantics

When merging two LWW-Maps (e.g., during `sigyn sync pull`):

- For each key present in both maps, the entry with the **later timestamp** wins.
- Keys present in only one map are copied to the merged result.

```rust
fn merge(&mut self, other: &LwwMap<V>) {
    for (key, other_entry) in &other.entries {
        match self.entries.get(key) {
            Some(local_entry) => {
                if other_entry.timestamp > local_entry.timestamp {
                    self.entries.insert(key.clone(), other_entry.clone());
                }
            }
            None => {
                self.entries.insert(key.clone(), other_entry.clone());
            }
        }
    }
}
```

This provides **automatic convergence**: all nodes that receive the same set of
updates will arrive at the same state, regardless of the order in which they
receive them.

## Conflict Detection and Resolution

When vector clocks indicate concurrent modifications to the same key, Sigyn records
a `Conflict`:

```rust
Conflict {
    key: String,
    env: String,
    local_value: String,
    remote_value: String,
    local_clock: VectorClock,
    remote_clock: VectorClock,
}
```

### Resolution Strategies

Conflicts can be resolved using one of six strategies:

| Strategy | Description |
|---|---|
| `TakeLocal` | Keep the local value, discard remote |
| `TakeRemote` | Keep the remote value, discard local |
| `TakeLatestTimestamp` | Keep whichever value has the later UTC timestamp (LWW) |
| `TakeHigherRole` | Keep the value written by the member with the higher RBAC role level |
| `Merge(value)` | Provide a custom merged value |
| `Defer` | Skip resolution; the conflict remains until resolved manually |

### Automatic vs Manual Resolution

The LWW-Map CRDT resolves non-conflicting updates automatically. When vector clocks
detect a true concurrent write (same key modified on two machines without syncing),
the conflict is surfaced to the user.

Resolve manually:

```bash
# List conflicts
sigyn sync status

# Resolve a specific conflict
sigyn sync resolve DATABASE_URL --strategy local
sigyn sync resolve API_KEY --strategy remote
sigyn sync resolve CONFIG --strategy latest
```

## Security Considerations

### Sync Never Needs the Master Key

All vault files are encrypted at rest. The sync layer operates on opaque encrypted
blobs. A git remote hosting Sigyn vaults cannot read any secret values -- it only
sees CBOR-encoded ciphertext.

### Audit Log Integrity Across Sync

The hash-chained audit log is included in sync. After pulling, you can verify the
chain to detect any tampering that may have occurred on the remote:

```bash
sigyn sync pull
sigyn audit verify
```

### Revocation Propagation

When a member is revoked on one machine, the updated `policy.cbor` and `members.cbor`
(with the revoked slot removed and master key rotated) are synced to all other members
on the next push/pull cycle. The revoked member's slot is no longer present in the
envelope header, so they cannot decrypt any data even if they pull the latest files.

### Vector Clocks Prevent Silent Overwrites

Concurrent modifications are always detected and surfaced via the conflict system.
No data is silently overwritten during sync.

## Workflow Example

A typical team workflow:

```bash
# Alice creates a vault and pushes
sigyn vault create myapp
sigyn secret set DATABASE_URL 'postgres://...' --env dev
sigyn sync configure --remote-url git@github.com:team/secrets.git
sigyn sync push

# Bob clones and pulls
sigyn sync pull --vault myapp

# Bob adds a secret and pushes
sigyn secret set API_KEY 'sk-...' --env dev
sigyn sync push

# Alice pulls Bob's changes
sigyn sync pull
sigyn secret list --env dev    # sees both DATABASE_URL and API_KEY

# If both Alice and Bob modify the same key simultaneously:
sigyn sync pull
# Output: Conflict detected on API_KEY (dev)
sigyn sync resolve API_KEY --strategy latest
sigyn sync push
```

## Related Documentation

- [Architecture](architecture.md) -- on-disk layout and module overview
- [Security Model](security.md) -- encryption and access control
- [Delegation](delegation.md) -- how revocations affect sync
- [CLI Reference](cli-reference.md) -- complete command reference
