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
3. Each entry's `signature` must be a valid Ed25519 signature from the claimed `actor`. A signature that fails against a known key is treated as tampering; an entry whose signing key is merely not available on this device is reported as *unverifiable* (a warning), not as tampering.
4. All sequence numbers from 0 to N must be present with no gaps, detecting selective deletion of individual entries.
5. **Tail truncation** — dropping the most recent entries leaves an otherwise-valid prefix, so Sigyn also records the audit chain tip `(sequence, hash)` in device-local state that is never synced through the vault's git repo. On verify (and after pull), the log must still contain that tip; if it no longer does, verification fails.

If any check fails, `sigyn audit verify` prints the broken link with the sequence number and reason **and exits with a non-zero status**, so it is safe to use in a gate such as `sigyn audit verify && deploy`. Unverifiable-key warnings do not cause a non-zero exit.

## Witness Countersigning

Witnesses provide independent verification. Any member can countersign an audit entry, creating a witness record that attests they observed the entry at a specific time:

```bash
sigyn audit witness
```

This is useful for compliance workflows where multiple parties must acknowledge sensitive operations.

The witness log itself is encrypted and optionally signed. When signed, the format is `SGNW || sig_len(4 LE) || Ed25519_signature || ciphertext`. The signature is verified on load when the owner's verifying key is available, preventing tampering with witness records.

## Audit Push Modes

Vaults have a configurable audit push mode, set in the signed policy (owner/admin only):

| Mode | Behavior |
|------|----------|
| `offline` | Default. Audit entries are appended locally; push when convenient via `sigyn sync push`. |
| `online` | Audit entries must be pushed to the remote after each operation. Operations fail if the push fails (e.g., SSH key locked, network down). Only enforced when a git remote is configured. |
| `best-effort` | Attempts to push audit entries after each operation. Warns on failure but doesn't block the operation. |

```bash
# Set audit mode (requires ManagePolicy access — owner/admin)
sigyn policy audit-mode online
sigyn policy audit-mode best-effort
sigyn policy audit-mode offline

# View current mode
sigyn policy show
```

**Design notes:**

- The mode is part of the signed `policy.cbor`, so members cannot tamper with it.
- New vaults default to `offline` — you must configure a git remote before `online` mode has any effect.
- `online` mode is a compliance guarantee: if audit can't reach the remote, the operation is rejected. This prevents exfiltration without audit visibility.

### Deploy Keys

For `online` and `best-effort` modes, you can generate a **sealed deploy key** so audit push works even when the user's SSH key is locked or unavailable:

```bash
# Generate a deploy key (sealed with vault cipher, stored in vault dir)
sigyn sync deploy-key generate

# Show the public key (add this to your git remote with push access)
sigyn sync deploy-key show-pubkey

# Remove the deploy key
sigyn sync deploy-key remove
```

The deploy key is:
- **Encrypted at rest** with the vault cipher — only vault members can use it
- **Ed25519** — passwordless, no passphrase prompt
- **Scoped** — should be added as a deploy key with push-only access to the audit/vault repo, not as a personal key
- **Not stored in plaintext** — the raw key bytes are sealed in `deploy_key.sealed`

When a deploy key exists, audit push uses it automatically. When absent, it falls back to the user's SSH agent / credential helper.

## Storage

The audit log is stored as JSON Lines in `audit.log.json` within the vault directory. Each line is individually encrypted with a vault-derived cipher (HKDF from the vault key with context `sigyn-audit-v1`) and base64-encoded. This format is streamable and compatible with external log analysis tools after decryption.
