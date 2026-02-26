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

- `VaultCreated`, `VaultDeleted`, `VaultExported`
- `SecretRead`, `SecretWritten`, `SecretDeleted`
- `SecretsCopied` — `sigyn secret copy` (records keys, source/dest envs)
- `SecretsExported` — `sigyn run export` (records env and format)
- `SecretsInjected` — `sigyn run exec` (records env and command)
- `SecretsServed` — `sigyn run serve` (records env)
- `SecretsListed` — `sigyn secret list` (records env)
- `MemberInvited`, `MemberRevoked`
- `PolicyChanged`
- `MasterKeyRotated`
- `OwnershipTransferred` — records from/to fingerprints
- `OwnershipTransferAccepted` — records accepting fingerprint
- `ForkCreated`
- `EnvironmentCreated`, `EnvironmentDeleted`, `EnvironmentPromoted`
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
3. Each entry's `signature` must be a valid Ed25519 signature from the claimed `actor`. Entries by actors not present in the vault policy are rejected (prevents forged entries by outsiders).
4. All sequence numbers from 0 to N must be present with no gaps, detecting selective deletion of individual entries.

If any check fails, `sigyn audit verify` reports the broken link with the sequence number and reason.

## Witness Countersigning

Witnesses provide independent verification. Any member can countersign an audit entry, creating a witness record that attests they observed the entry at a specific time:

```bash
sigyn audit witness
```

This is useful for compliance workflows where multiple parties must acknowledge sensitive operations.

The witness log itself is encrypted and optionally signed. When signed, the format is `SGNW || sig_len(4 LE) || Ed25519_signature || ciphertext`. The signature is verified on load when the owner's verifying key is available, preventing tampering with witness records.

## Storage

The audit log is stored as JSON Lines in `audit.log.json` within the vault directory. Each line is individually encrypted with a vault-derived cipher (HKDF from the vault key with context `sigyn-audit-v1`) and base64-encoded. This format is streamable and compatible with external log analysis tools after decryption.
