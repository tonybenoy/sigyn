# Audit System

Every operation in Sigyn is recorded in an append-only, hash-chained audit log. Each entry is signed with the acting member's Ed25519 key.

## Audit Entries

Each log entry contains:

| Field | Description |
|-------|-------------|
| `sequence` | Monotonic sequence number |
| `timestamp` | ISO 8601 UTC timestamp |
| `actor` | Fingerprint of the acting member |
| `action` | Operation type (see below) |
| `env` | Environment affected (if applicable) |
| `key` | Secret key affected (if applicable) |
| `outcome` | Success or failure with reason |
| `prev_hash` | blake3 hash of the previous entry |
| `entry_hash` | blake3 hash of this entry |
| `signature` | Ed25519 signature over `entry_hash` |

## Tracked Actions

- `VaultCreated`, `VaultDeleted`
- `SecretRead`, `SecretWritten`, `SecretDeleted`
- `MemberInvited`, `MemberRevoked`
- `PolicyChanged`
- `MasterKeyRotated`
- `ForkCreated`
- `EnvCreated`, `EnvPromoted`
- `BreakGlassActivated`

## Commands

```bash
# View recent entries
sigyn audit tail -n 20

# Query by actor, action, or time range
sigyn audit query --actor <fingerprint> --action SecretWritten

# Verify the entire chain (hashes + signatures)
sigyn audit verify

# Export audit log
sigyn audit export --format json > audit-export.json

# Add a witness countersignature to the latest entry
sigyn audit witness

# Anchor to git (embed hash in commit message)
sigyn audit anchor
```

## Tamper Detection

The audit chain is tamper-evident by construction:

1. Each entry's `prev_hash` must match the `entry_hash` of the preceding entry.
2. Each entry's `entry_hash` must be a valid blake3 hash of the entry content.
3. Each entry's `signature` must be a valid Ed25519 signature from the claimed `actor`.

If any check fails, `sigyn audit verify` reports the broken link with the sequence number and reason.

## Witness Countersigning

Witnesses provide independent verification. Any member can countersign an audit entry, creating a witness record that attests they observed the entry at a specific time:

```bash
sigyn audit witness
```

This is useful for compliance workflows where multiple parties must acknowledge sensitive operations.

## Storage

The audit log is stored as JSON Lines in `audit.log.json` within the vault directory. This format is streamable, grep-friendly, and compatible with external log analysis tools.
