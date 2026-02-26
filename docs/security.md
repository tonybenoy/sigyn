# Sigyn Security Model

This document describes the cryptographic primitives, access control system, and
security properties of Sigyn.

## Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|---|---|---|
| Key exchange | X25519 (Curve25519 Diffie-Hellman) | Derive shared secrets for envelope encryption |
| Signatures | Ed25519 | Sign audit entries, invitation files, identity verification |
| Symmetric encryption | ChaCha20-Poly1305 (AEAD) | Encrypt secret data and master key slots |
| Key derivation (passphrase) | Argon2id | Derive wrapping key from user passphrase |
| Key derivation (context) | HKDF-SHA256 | Derive per-slot keys from DH shared secrets |
| Hashing / fingerprints | BLAKE3 | Audit chain hashing, key fingerprints |

All cryptographic operations use audited Rust crates from the RustCrypto project:
`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `argon2`, `hkdf`, `blake3`.

## Envelope Encryption

Sigyn uses envelope encryption to allow multiple members to access a vault without
sharing a single passphrase. The scheme works as follows:

```
                    +-------------------+
                    |   Master Key      |  (random 256-bit, encrypts all secrets)
                    +-------------------+
                            |
              +-------------+-------------+
              |             |             |
        +-----------+ +-----------+ +-----------+
        | Slot: Alice| | Slot: Bob | | Slot: Carol|
        +-----------+ +-----------+ +-----------+
        | ephemeral  | | ephemeral  | | ephemeral  |
        | X25519 pub | | X25519 pub | | X25519 pub |
        | encrypted  | | encrypted  | | encrypted  |
        | master key | | master key | | master key |
        +-----------+ +-----------+ +-----------+
```

### Sealing (encrypt master key for a recipient)

1. Generate an ephemeral X25519 keypair.
2. Perform Diffie-Hellman: `shared_secret = ephemeral_private * recipient_public`.
3. Derive a slot key via HKDF-SHA256: `slot_key = HKDF(salt=vault_id, ikm=shared_secret, info="sigyn-envelope-v1")`.
4. Encrypt the master key with ChaCha20-Poly1305 using the slot key and a random nonce.
5. Store `(recipient_fingerprint, ephemeral_public_key, nonce || ciphertext)` as the slot in the `EnvelopeHeader`.

### Unsealing (decrypt master key)

1. Find the `RecipientSlot` matching your key fingerprint in the `EnvelopeHeader`.
2. Perform Diffie-Hellman: `shared_secret = my_private * slot.ephemeral_public`.
3. Derive the same slot key via HKDF-SHA256 with the vault UUID as salt.
4. Decrypt the master key with ChaCha20-Poly1305.

### Key Properties

- Each slot uses a unique ephemeral keypair, so compromising one slot reveals nothing about others.
- The vault UUID is used as HKDF salt, binding each slot key to a specific vault.
- Adding or removing a member only requires re-encrypting the master key, not re-encrypting all secrets.
- On member revocation, the master key is rotated and all remaining slots are rebuilt with the new key.

## Identity

Each Sigyn user has an identity consisting of two keypairs:

| Keypair | Algorithm | Purpose |
|---|---|---|
| Encryption keypair | X25519 | Receive sealed master key slots |
| Signing keypair | Ed25519 | Sign audit entries, invitations |

Both keypairs are stored on disk encrypted with an Argon2id-derived key from the user's
passphrase. The identity is identified by its key fingerprint, which is a BLAKE3 hash
of the X25519 public key truncated to 128 bits (16 bytes), displayed as a hex string.

### Passphrase Protection

```
passphrase --> Argon2id --> wrapping_key --> ChaCha20-Poly1305 --> encrypted keypairs on disk
```

The Argon2id parameters are chosen for interactive use (moderate memory and time cost).
When the user runs any command that needs their private key, they are prompted for
their passphrase. The wrapping key is held in a `secrecy::Secret` and zeroed on drop.

### On-Disk Layout

```
~/.sigyn/identities/<name>/
  identity.toml             # Metadata: name, fingerprint, email, created_at
  secret_key.enc            # Argon2id-wrapped Ed25519 + X25519 keypair
```

## Role-Based Access Control (RBAC)

Sigyn implements a 7-level role hierarchy. Each role inherits all permissions of lower
roles:

| Level | Role | Read | Write | Manage Members | Manage Policy | Delegate |
|---|---|---|---|---|---|---|
| 1 | **ReadOnly** | yes | no | no | no | no |
| 2 | **Auditor** | yes | no | no | no | no |
| 3 | **Operator** | yes | no | no | no | no |
| 4 | **Contributor** | yes | yes | no | no | no |
| 5 | **Manager** | yes | yes | yes | no | yes |
| 6 | **Admin** | yes | yes | yes | yes | yes |
| 7 | **Owner** | yes | yes | yes | yes | yes |

The Owner is the vault creator and always bypasses policy checks. There is exactly one
Owner per vault.

### Permission Breakdown

- **Read**: decrypt and view secret values (all roles).
- **Write**: set or delete secrets (Contributor and above).
- **Manage Members**: add/remove members, create invitations (Manager and above).
- **Manage Policy**: modify RBAC rules, constraints, and ACLs (Admin and above).
- **Delegate**: create invitations for new members, limited to roles at or below your own (Manager and above).

## Policy Engine

Every secret access goes through `PolicyEngine::evaluate()`. There is no code path
that reads or writes secrets without a policy check. The engine evaluates the following
in order:

1. **Owner bypass**: if the actor is the vault owner, access is always granted.
2. **Membership check**: the actor must be a registered vault member.
3. **Constraint check**: if the member has constraints (time windows, expiry, MFA), they are all evaluated. Any failure results in denial.
4. **Environment check**: the member must have explicit access to the requested environment (or wildcard `*`).
5. **Role check**: the member's role must have the required permission for the action (read, write, delete, manage members, manage policy, create env, promote).
6. **Secret pattern check**: if the member has secret-level ACL patterns, the requested key must match at least one allowed pattern (glob syntax: `DB_*`, `AWS_*`, `*_SECRET`).

The engine returns one of three decisions:

- `Allow` -- access granted.
- `Deny(reason)` -- access denied with an explanation string.
- `AllowWithWarning(message)` -- access granted but with a warning.

## Constraints

Members can have constraints attached to their access:

### Time Windows

```rust
TimeWindow {
    days: [Mon, Tue, Wed, Thu, Fri],
    start_hour: 9,
    end_hour: 17,
}
```

If any time windows are defined for a member, at least one must match the current
time for access to be granted. Supports overnight windows (e.g., `start_hour: 22`,
`end_hour: 6` wraps past midnight).

### Expiry

Members can have an `expires_at` timestamp. After expiry, all access is denied
regardless of role.

### MFA (Multi-Factor Authentication)

When `require_mfa: true` is set on global or member constraints, the policy engine
returns `RequiresMfa` instead of `Allow`. The CLI then:

1. Checks for a valid MFA session (default grace period: 1 hour).
2. If no session, loads the encrypted `.mfa` file (decrypted with a key derived via
   HKDF-SHA256 from the identity's X25519 private key with context `b"mfa-state"`).
3. Prompts for a TOTP code or single-use backup code.
4. On success, creates a session file (HMAC-protected with blake3) so subsequent
   operations within the grace period skip the prompt.

MFA state is stored per identity at `~/.sigyn/identities/<fingerprint>.mfa`,
encrypted with ChaCha20-Poly1305. Sessions are stored at
`~/.sigyn/sessions/<fingerprint>.session`.

Backup codes are hashed with blake3 before storage and verified using constant-time
comparison to prevent timing side-channel attacks. Each backup code is consumed on
use and cannot be reused. Session HMACs are also compared in constant time.

## Per-Key ACLs

Beyond role-based access, individual secrets can have fine-grained ACLs via `SecretAcl`:

| Variant | Meaning |
|---|---|
| `Everyone` | All members with sufficient role can access (default) |
| `Roles(set)` | Only members with one of the listed roles |
| `Fingerprints(set)` | Only the listed key fingerprints |
| `Deny` | Explicitly deny all access |

Each secret key can have separate read and write ACLs via the `KeyAcl` struct.
Additionally, members can be restricted to secrets matching specific glob patterns
(e.g., `DB_*`, `AWS_*`, `*_SECRET`).

## Delegation

See [Delegation](delegation.md) for a full deep dive. Key security properties:

- Members can only delegate roles **strictly below** their own level (e.g., a Manager can invite Contributors but not Managers). The Owner can invite any role except Owner.
- Each delegation records `delegated_by`, forming a tree rooted at the Owner.
- **Cascade revocation**: revoking a member revokes everyone they invited, transitively (BFS traversal of the delegation tree).
- **Master key rotation on revoke**: when any member is revoked, a new master key is generated via `VaultCipher::generate()` and re-encrypted to all remaining members. The revoked subtree immediately loses decryption access.

## Audit Trail

Sigyn maintains a hash-chained, signed audit log for every vault, stored as JSON Lines
at `<vault>/audit.log.json`.

### Entry Structure

Each `AuditEntry` contains:

- `sequence`: monotonically increasing counter.
- `timestamp`: UTC timestamp.
- `actor`: BLAKE3 key fingerprint of the actor.
- `action`: what was done (`SecretRead`, `SecretWritten`, `SecretDeleted`, `VaultCreated`, `MemberRevoked`, `PolicyChanged`, `MasterKeyRotated`, `EnvironmentCreated`, `EnvironmentPromoted`, etc.).
- `env`: which environment was affected (optional).
- `outcome`: `Success` or `Failure(reason)`.
- `nonce`: 16-byte random nonce (prevents rainbow table attacks on the hash chain).
- `prev_hash`: BLAKE3 hash of the previous entry (or null for the first entry).
- `entry_hash`: BLAKE3 hash of `(sequence, timestamp, actor, nonce, prev_hash)`.
- `signature`: Ed25519 signature over `entry_hash` by the actor.

### Security Properties

- **Hash chain**: each entry includes the hash of the previous entry. Tampering with
  or removing any entry breaks the chain, which is detected by `sigyn audit verify`.
- **Ed25519 signatures**: each entry is signed by the actor's Ed25519 key, proving
  authorship and preventing forgery.
- **Append-only**: the log file is opened in append mode only.
- **Witness countersigning**: a second party can countersign the latest entry to provide
  independent verification via `sigyn audit witness`. Witness signatures are stored
  separately in a `WitnessLog`.
- **External anchoring**: audit hashes can be anchored to external systems for
  additional tamper evidence.

### Verification

```bash
sigyn audit verify
```

This walks the entire log, verifying that each entry's `prev_hash` matches the
preceding entry's `entry_hash`. Any break in the chain is reported with the
sequence number of the first invalid entry (`SigynError::AuditChainBroken(seq)`).

## Shamir Secret Sharing (Recovery)

For disaster recovery, Sigyn implements K-of-N Shamir secret sharing over GF(256):

- The identity encryption private key is split into N shards.
- Any K shards (where K <= N) can reconstruct the original key.
- Fewer than K shards reveal zero information about the key (information-theoretic security).

Implementation details:

- Arithmetic is performed in GF(256) with irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B).
- Polynomial evaluation uses Horner's method.
- Reconstruction uses Lagrange interpolation at x=0.
- Inverse computation uses Fermat's little theorem: `a^(-1) = a^254` in GF(256).

Typical usage: split into 5 shards with threshold 3, distribute to trusted parties.

```bash
sigyn-recovery split --identity alice --threshold 3 --total 5
sigyn-recovery restore shard-*.json
```

The standalone `sigyn-recovery` binary is intentionally minimal so it can be
distributed independently of the main CLI.

## Fork Isolation

Vaults can be forked in two modes:

| Mode | Description | Upstream Access |
|---|---|---|
| **Leashed** | Fork stays connected to the parent vault. The upstream owner retains the ability to revoke or expire the fork. Changes can be synced back. | Parent retains access |
| **Unleashed** | Fork is fully independent. A new master key is generated. No connection to the parent vault remains. | Fully severed |

Fork policies control sharing mode, max drift (days without syncing), revocation
inheritance, and whether the fork can add members independently.

## Memory Safety

- All private key material is wrapped in `secrecy::Secret<T>` which zeroes memory on drop via the `zeroize` crate.
- Decrypted secret values are never written to disk in plaintext.
- The CLI never logs or prints private keys.

## Atomic File Writes

All file writes in the CLI go through a write-to-temp-then-persist pattern using
`tempfile::NamedTempFile` and its `persist()` method. This prevents partial writes
from corrupting vault data if the process is interrupted. The `fd-lock` crate provides
advisory file locking for concurrent access safety.

## Threat Model Summary

| Threat | Mitigation |
|---|---|
| Stolen vault files | ChaCha20-Poly1305 encryption; attacker needs a member's private key |
| Compromised member | Revoke member; master key is rotated; cascade revocation removes their delegates |
| Tampered audit log | Hash chain breaks on tamper; Ed25519 signatures prove authorship |
| Lost access (key loss) | Shamir K-of-N recovery shards |
| Unauthorized access escalation | `PolicyEngine::evaluate()` on every operation; no bypass path |
| Brute-force passphrase | Argon2id with tuned memory/time cost |
| Stolen credentials (passphrase only) | Optional TOTP-based MFA as second factor; session grace period limits exposure window |
| Replay of old ciphertext | Unique nonces per encryption; vault UUID bound into HKDF salt |
| Sensitive data in memory | `secrecy::Secret` + `zeroize` on drop |
| Partial file writes | Atomic writes via `tempfile::persist()` |

## Related Documentation

- [Architecture](architecture.md) -- project structure and module overview
- [CLI Reference](cli-reference.md) -- complete command reference
- [Delegation](delegation.md) -- invitation and revocation deep dive
- [Sync](sync.md) -- synchronization and conflict resolution
