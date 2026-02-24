# Disaster Recovery

Sigyn includes a standalone recovery binary (`sigyn-recovery`) and Shamir secret sharing for disaster recovery scenarios.

## Shamir Secret Sharing

Sigyn can split the vault master key (or identity private key) into K-of-N shards using Shamir's Secret Sharing over GF(256). Any K shards are sufficient to reconstruct the secret; fewer than K reveal nothing.

### Creating Recovery Shards

```bash
# Split into 5 shards, requiring any 3 to recover
sigyn recovery shards print --threshold 3 --total 5
```

This outputs shard data that can be:
- Printed on paper and stored in separate secure locations
- Encoded as QR codes for easy scanning
- Distributed to trusted parties

### Recovering from Shards

```bash
sigyn-recovery restore --shards shard1.json,shard2.json,shard3.json
```

The standalone `sigyn-recovery` binary can reconstruct the master key from K shards without needing an unlocked identity.

## Vault Snapshots

Since vaults are stored as files in a git repository, every commit is a recoverable snapshot:

```bash
# List available snapshots
sigyn recovery snapshots

# Restore from a specific snapshot
sigyn recovery snapshots --restore <commit-hash>
```

## Recovery Binary

The `sigyn-recovery` binary is a minimal standalone tool that can:

1. Reconstruct secrets from Shamir shards
2. Restore a vault from a git snapshot
3. Operate without an existing Sigyn installation

It is intentionally kept separate from the main CLI to reduce the attack surface and ensure it works even if the primary installation is compromised.

## Best Practices

- Store shards in geographically separate locations
- Use a threshold that balances availability and security (e.g., 3-of-5)
- Test recovery procedures periodically
- Keep the `sigyn-recovery` binary alongside your shard backups
- Document your recovery plan and shard holder contacts outside of Sigyn
