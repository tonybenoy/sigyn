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

Sigyn uses envelope encryption with **per-environment key isolation** to allow
multiple members to access a vault without sharing a single passphrase, while
cryptographically enforcing environment-level access boundaries.

### Two-Tier Key Architecture

Each vault has two tiers of symmetric keys:

1. **Vault key** (256-bit) -- encrypts vault-level metadata: manifest, policy, audit log, rotation schedules.
2. **Per-environment keys** (256-bit each) -- each environment (`dev`, `staging`, `prod`, etc.) has its own independent key that encrypts only that environment's secret data.

```
                    +-------------------+
                    |   Vault Key       |  (encrypts manifest, policy, audit)
                    +-------------------+
                            |
              +-------------+-------------+
              |             |             |
        +-----------+ +-----------+ +-----------+
        | Slot: Alice| | Slot: Bob | | Slot: Carol|  (vault_key_slots)
        +-----------+ +-----------+ +-----------+


    +-------------------+  +-------------------+  +-------------------+
    |  Dev Env Key      |  | Staging Env Key   |  |  Prod Env Key     |
    +-------------------+  +-------------------+  +-------------------+
            |                       |                       |
      +-----------+           +-----------+           +-----------+
      | Slot: Alice|          | Slot: Alice|          | Slot: Alice|
      | Slot: Bob  |          | Slot: Alice|          +-----------+
      | Slot: Carol|          | Slot: Bob  |
      +-----------+           +-----------+           (env_slots)
```

A member only receives slots for environments they are authorized to access. A
Contributor with `allowed_envs: ["dev"]` physically cannot decrypt `prod` secrets
because they never receive the prod environment key. This is a **cryptographic
barrier**, not just a policy-layer check.

### Sealing (encrypt a key for a recipient)

1. Generate an ephemeral X25519 keypair.
2. Perform Diffie-Hellman: `shared_secret = ephemeral_private * recipient_public`.
3. Derive a slot key via HKDF-SHA256: `slot_key = HKDF(salt=vault_id, ikm=shared_secret, info="sigyn-envelope-v1")`.
4. Encrypt the key with ChaCha20-Poly1305 using the slot key and a random nonce.
5. Store `(recipient_fingerprint, ephemeral_public_key, nonce || ciphertext)` as the slot.

For vault key slots, the AEAD Additional Authenticated Data (AAD) is
`fingerprint || vault_id`. For environment key slots, the AAD is
`fingerprint || vault_id || env_name_len (4 LE bytes) || env_name_bytes`.
The length prefix prevents collisions between environment names (e.g., "dev" + "prod"
cannot be confused with "devprod").

### Unsealing

1. Find the `RecipientSlot` matching your key fingerprint.
2. Perform Diffie-Hellman: `shared_secret = my_private * slot.ephemeral_public`.
3. Derive the same slot key via HKDF-SHA256 with the vault UUID as salt.
4. Decrypt the key with ChaCha20-Poly1305.

For vault operations (manifest, policy, audit), unseal from `vault_key_slots`.
For environment operations, unseal the specific environment key from `env_slots[env_name]`.

### Key Properties

- Each slot uses a unique ephemeral keypair, so compromising one slot reveals nothing about others.
- The vault UUID is used as HKDF salt, binding each slot key to a specific vault.
- Environment names are bound into the AAD, preventing cross-environment slot reuse.
- A member without a slot for a given environment **cannot** decrypt that environment's secrets, regardless of any policy bypass.
- On member revocation, only the affected environment keys are rotated and re-sealed to remaining members. Unaffected environments are untouched.
- Adding a member to a new environment requires the inviter to hold that environment's key -- you cannot grant access you don't have.

## Identity

Each Sigyn user has an identity consisting of two keypairs:

| Keypair | Algorithm | Purpose |
|---|---|---|
| Encryption keypair | X25519 | Receive sealed vault and environment key slots |
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

Policy files (`policy.cbor`) are encrypted with the vault cipher and Ed25519-signed
(SGSN format). The signature binds the policy to the vault UUID, preventing tampering
and cross-vault replay. All policy files must be signed; unsigned files are rejected.

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
4. On success, creates a session file (HMAC-protected with a key derived via
   HKDF from the device key with context `b"sigyn-session-hmac-v1"`) so subsequent
   operations within the grace period skip the prompt.

MFA state is stored per identity at `~/.sigyn/identities/<fingerprint>.mfa`,
encrypted with ChaCha20-Poly1305 using the identity's fingerprint as AEAD
Associated Authenticated Data (AAD). This binds the MFA ciphertext to the specific
identity — copying an MFA file from one identity to another will fail decryption.
Sessions are stored at `~/.sigyn/sessions/<fingerprint>.session` with `0o600`
permissions in a `0o700` directory.

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
- **Vault key rotation on revoke**: the vault-level encryption key is rotated immediately upon revocation. A new random key is generated and re-sealed to the remaining authorized members only. The revoked member's cached vault key can no longer decrypt policy, manifest, or audit data written after revocation.
- **Per-environment key rotation on revoke**: in addition to the vault key, only the environment keys the revoked member had access to are rotated. Each affected environment gets a new random key, re-sealed to the remaining authorized members. Unaffected environments are untouched. The revoked member (and their cascade subtree) immediately lose decryption access.
- **Invitation expiry**: invitations are created with a 7-day expiry (`expires_at`). Attempting to accept an expired invitation is rejected with a clear error message. This limits the window for invitation file theft or replay.

## Audit Trail

Sigyn maintains a hash-chained, signed, and encrypted audit log for every vault,
stored at `<vault>/audit.log.json`. Each line is individually encrypted with a
vault-derived cipher (HKDF from the vault key with context `sigyn-audit-v1` and
vault_id as salt), then base64-encoded.

### Entry Structure

Each `AuditEntry` contains:

- `sequence`: monotonically increasing counter.
- `timestamp`: UTC timestamp.
- `actor`: BLAKE3 key fingerprint of the actor.
- `action`: what was done (`SecretRead`, `SecretWritten`, `SecretDeleted`, `VaultCreated`, `MemberRevoked`, `PolicyChanged`, `MasterKeyRotated`, `EnvironmentCreated`, `EnvironmentPromoted`, `SecretsExported`, `SecretsInjected`, `SecretsServed`, `SecretsListed`, etc.).
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
- **Append-only**: the log file is opened in append mode only. The reader tolerates
  a single trailing corrupt line (crash recovery for interrupted writes) while still
  detecting mid-file tampering.
- **Witness countersigning**: a second party can countersign the latest entry to provide
  independent verification via `sigyn audit witness`. Witness signatures are stored
  separately in a `WitnessLog`.
- **External anchoring**: audit hashes can be anchored to external systems for
  additional tamper evidence.

### Verification

```bash
sigyn audit verify
```

This walks the entire log and verifies:

1. **Hash linkage**: each entry's `prev_hash` matches the preceding entry's `entry_hash`.
2. **Hash integrity**: each entry's `entry_hash` is recomputed and compared.
3. **Ed25519 signatures**: each entry's signature is verified against the actor's public key from the vault policy. Entries by unknown actors (not in policy) are rejected.
4. **Sequence continuity**: all sequence numbers from 0 to N must be present with no gaps, detecting selective deletion of entries.

Any break is reported with the sequence number of the first invalid entry (`SigynError::AuditChainBroken(seq)`).

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
inheritance, and whether the fork can add members independently. Fork envelope
headers are SGSN-signed and fork policy files are signed, both bound to the fork's
vault UUID.

## Memory Safety

- All private key material is wrapped in `secrecy::Secret<T>` which zeroes memory on drop via the `zeroize` crate.
- Ephemeral slot keys (HKDF-derived) are wrapped in `Zeroizing<>` and zeroed immediately after use.
- Ed25519 signing keys use `ZeroizeOnDrop` from `ed25519-dalek`.
- Key fingerprint comparisons use constant-time equality (`subtle::ConstantTimeEq`) to prevent timing side-channels.
- Decrypted secret values are never written to disk in plaintext.
- The CLI never logs or prints private keys.
- Clipboard copies are automatically cleared after 30 seconds via a background thread
  guarded by an `AtomicBool` to prevent double-clear races.
- Passphrase strings are explicitly zeroized at CLI call sites after use.

## Atomic File Writes

All file writes in the CLI go through a write-to-temp-then-persist pattern using
`tempfile::NamedTempFile` and its `persist()` method. This prevents partial writes
from corrupting vault data if the process is interrupted. The `fd-lock` crate provides
advisory file locking for concurrent access safety, with lock files created at `0o600`
permissions.

The `secure_write()` function on Unix creates a temporary file with `0o600` mode from
the start (via `OpenOptions::mode()`), writes content, calls `sync_all()` for
durability, and atomically renames to the target path. This eliminates the TOCTOU
window where a file could be briefly readable with default permissions between
creation and `chmod`.

**Symlink protection:** Before writing, `atomic_write()` walks every component of the
target path and rejects the operation if any component is a symlink. This prevents both
direct symlink files and symlinked parent directories from redirecting writes outside the
vault. The check applies to both new and existing files.

## Filesystem Permissions

Sigyn enforces restrictive Unix permissions on all files it manages:

- **`~/.sigyn/` directory**: created with `0o700` (owner only) to prevent other local
  users from reading vault metadata, config, or manifests.
- **Encrypted files** (policy, secrets, identities): written via `atomic_write()` with
  `0o600` permissions (owner read/write only).
- **Audit log files**: `0o600` permissions enforced on creation via `OpenOptions`.
- **Witness log files**: `0o600` permissions enforced after atomic persist.
- **Lock files**: `0o600` permissions enforced (errors propagated, not silently dropped).
- **All other files** (manifests, config, context, notifications): also encrypted and
  written via `secure_write()` with `0o600` permissions.

## Encrypted File Protection

Every file under `~/.sigyn/` is either encrypted (AEAD) or cryptographically signed.
A three-tier key hierarchy ensures each file is protected with the appropriate key
available at read time:

### Tier A: Device Key

A 32-byte random key stored at `~/.sigyn/.device_key` (mode `0o400`). Generated on
first use. The file is 64 bytes: the key followed by a BLAKE3 integrity hash
(`BLAKE3(key || "sigyn-device-key-v1")`). The hash is verified on every load;
tampered files are rejected. Protects files that must be readable **before** any
identity is loaded:

| File | HKDF Context |
|---|---|
| `config.toml` | `sigyn-config-v1` |
| `context.toml` | `sigyn-context-v1` |
| `notifications.toml` | `sigyn-notifications-v1` |
| `org-manifest.toml` | `sigyn-org-manifest-v1` |
| `forks.cbor` | `sigyn-forks-v1` |

### Tier B: Identity Signing Key (Ed25519)

The `members.cbor` envelope header is wrapped in a signed file format (`SGSN` magic)
with an Ed25519 signature covering `blake3(cbor_data \|\| vault_id_bytes)`. This
provides integrity verification before the vault master key is available.

The `EnvelopeHeader` includes a `vault_id` field, allowing the vault ID to be read
from `members.cbor` before decrypting `vault.toml` — breaking the circular dependency
that would otherwise require the manifest to be plaintext. The signature is verified
after vault unlock using the owner's signing key from the local identity store.

Invitation acceptance requires the inviter's identity to be present locally for
signature verification. This prevents accepting tampered invitations even when the
inviter is offline. Invitations use a length-prefixed signing payload (v2 format)
where every variable-length field is preceded by its byte length as a little-endian
`u32`, and list fields include an element count prefix. This prevents field boundary
ambiguity attacks where crafted values in one field could be interpreted as part of
another.

Hierarchy node `members.cbor` files also use the SGSN signed format with Ed25519
signatures, always verified on read. Hierarchy policy files (`policy.cbor`) at every
org node level are signed and bound to the node UUID, identical to vault-level policies.

### Tier C: Vault Key and Per-Environment Keys

After vault unlock, vault-level files are protected by a cipher derived from the
vault key, and each environment file is protected by its own independent key:

**Vault key** -- protects metadata files via HKDF-derived ciphers:

| File | HKDF Context | HKDF Salt |
|---|---|---|
| `vault.toml` (manifest) | `sigyn-manifest-v1` | (AAD = vault_id) |
| `rotation_schedules.toml` | `sigyn-rotation-v1` | vault_id |
| `audit.log.json` entries | `sigyn-audit-v1` | vault_id |
| `witnesses.json` | `sigyn-witness-v1` | vault_id |
| `deploy_key.sealed` | `sigyn-deploy-key-v1` (AAD) | — |

**Per-environment keys** -- each `envs/<name>.vault` file is encrypted with that
environment's dedicated 256-bit key, using the environment name as AEAD AAD.
Members only receive env key slots for environments in their `allowed_envs` list.

### Sealed File Format

Encrypted files use the `SGYN` sealed format:

```
[magic: "SGYN" 4B] [version: 0x01 1B] [nonce: 12B] [ciphertext + Poly1305 tag]
```

Signed files use the `SGSN` signed format:

```
[magic: "SGSN" 4B] [version: 0x01 1B] [cbor_data] [signature: 64B Ed25519]
```

### No Plaintext Fallbacks

All file readers strictly require their expected format (`SGYN` magic for encrypted
files, `SGSN` magic for signed files). There are no legacy plaintext fallbacks. If a
file does not have the correct magic header, it is rejected with a clear error. This
prevents downgrade attacks where an attacker replaces an encrypted file with a
plaintext version to bypass integrity checks.

## Rollback Protection

An attacker with push access to a vault's git remote could force-push older commits,
restoring a pre-revocation `members.cbor` that still includes a revoked member's slot.
Sigyn prevents this with commit-level rollback detection:

### Sync Checkpoints

After every successful `sync pull` or `sync push`, the current HEAD commit OID is
recorded in the device-local `pinned_vaults.cbor` store (encrypted with the device
key). On the next `sync pull`, Sigyn verifies that the fetched remote HEAD is a
**descendant** of the stored checkpoint using `git2::graph_descendant_of()`.

If the remote HEAD does not descend from the checkpoint, the pull is **aborted** with
an SSH-style warning banner:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: POSSIBLE ROLLBACK ATTACK   @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

The user must explicitly pass `--force` to accept the new remote state.

### Audit Checkpoints

Sigyn writes signed audit checkpoints (`audit.checkpoint`) after policy changes and
key rotations. A checkpoint records the current audit log sequence number and entry
hash, CBOR-serialized and Ed25519-signed (SGSN format bound to the vault UUID).

After a pull, the audit chain is verified against the stored checkpoint. If the entry
at the expected sequence no longer has the expected hash, the audit log has been
tampered with or rolled back.

### Git Commit Signing

Each sync commit is accompanied by a sidecar signature file (`.sigyn-commit-sig`)
containing the commit OID signed with the user's Ed25519 key. On pull, the signature
is verified against the committer's public key. Missing signature files are rejected.

## Vault Origin Pinning (TOFU)

Sigyn uses Trust-On-First-Use to prevent a vault copy-and-rehost attack:

1. **First access**: When a vault is unlocked for the first time on a device, the
   vault ID and owner fingerprint are recorded in the device-local `pinned_vaults.cbor`.
   A prominent warning banner is displayed urging the user to verify the owner
   fingerprint out-of-band. For automated workflows, set `SIGYN_VERIFY_OWNER=<fingerprint>`
   to require a match before the pin is saved — a mismatch aborts the unlock.
2. **Subsequent accesses**: The vault ID and owner fingerprint are verified against
   the pin. If either has changed, the unlock is aborted with an SSH-style warning:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: VAULT OWNER CHANGED        @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

This prevents an attacker from copying vault files, re-signing `members.cbor` with
their own key, and inviting victims to a different repo. Even though the entire
cryptographic chain passes, the pin check catches the owner substitution.

To accept a legitimate ownership change: `sigyn vault trust <name> --accept-new-owner`.

## Vault/Audit Repo Split

By default, vault data and audit data share a single git repo. This means an auditor
who needs push access to write witness entries also has push access to `members.cbor`.
Git hosting cannot enforce per-file permissions.

Sigyn supports an optional **split-repo layout** where audit data lives in a separate
git repository:

```
vaults/<name>/          # vault repo (members, policy, secrets)
  vault.toml
  members.cbor
  policy.cbor
  envs/
  .gitignore            # ignores audit/
  audit/                # separate git repo (audit log, witnesses)
    .git/
    audit.log.json
    witnesses.json
```

Created with `sigyn vault create <name> --split-audit`. This allows git hosting to
grant auditors **read** access to the vault repo (to unseal the audit cipher) and
**write** access only to the audit repo. Sync operations coordinate both repos
automatically, with independent rollback protection for each.

## Local State Store

Device-local state that is **never synced** is stored in `~/.sigyn/pinned_vaults.cbor`,
encrypted with a cipher derived from the device key (HKDF context
`b"sigyn-pinned-vaults-v1"`). This store holds:

- **Vault pins**: TOFU owner fingerprint and vault ID, recorded on first access.
- **Sync checkpoints**: last-known HEAD commit OIDs for rollback detection.
- **Audit checkpoints**: last-known audit sequence and entry hash.

## Encrypted Org Links

The `.org_link` metadata file (which records a vault's org hierarchy membership) is
encrypted with a device-key-derived cipher (HKDF context `b"sigyn-org-link-v1"`)
using the sealed file format.

## Project Config Trust

The `.sigyn.toml` file provides per-project defaults (vault name, environment,
identity). Because it is typically committed to a git repository, it can be
modified by anyone with push access. Sigyn applies the following safeguards:

- **Git-tracked warning**: when `.sigyn.toml` is loaded from a directory that
  contains a `.git` directory (or any parent does), a warning is printed:
  `warning: using .sigyn.toml from git-tracked directory — verify this file was not modified by an untrusted party`.
- **Identity override protection**: if `.sigyn.toml` sets the `identity` field
  (which controls which identity is used for all operations), Sigyn prints an
  additional warning and requires the `SIGYN_TRUST_PROJECT_CONFIG` environment
  variable to be set. Without it, the identity override is ignored with a warning.
  This prevents an attacker from silently redirecting vault operations to a
  compromised identity by modifying a committed config file.

## AI Coding Agent Threat Model

AI coding assistants (Claude Code, Cursor, GitHub Copilot, Windsurf, etc.) present a
new secret exposure surface: they run in your terminal with access to environment
variables, `.env` files, shell history, and process listings.

### Attack vectors

| Vector | How agent sees secrets |
|---|---|
| Environment variables | `env`, `printenv`, `/proc/self/environ` |
| `.env` files | `cat .env`, file reading tools |
| Shell history | `history`, `~/.bash_history` |
| Process listing | `ps aux` shows command-line args with inline secrets |
| Conversation context | Secrets pasted into prompts or visible in tool output |

### Sigyn mitigations

| Method | Protection level | How it works |
|---|---|---|
| `sigyn run exec` | Strong | Secrets injected as env vars into child process only; parent shell (where agent runs) is clean |
| `sigyn run --clean` | Stronger | Child process gets a clean environment with only vault secrets; no inherited vars leak |
| `sigyn run serve` | Strongest | Secrets served over a Unix socket with 0600 permissions; never appear in env vars or process listings |
| `.sigyn.toml` named commands | Convenience | `sigyn run dev` — developers never type or see secrets |
| `sigyn web` | GUI alternative | Manage secrets in a browser; no terminal exposure at all |

### Recommended workflow

1. **Never** `export` secrets or use `source .env` in terminals where AI agents run.
2. Use `sigyn run exec` or named commands in `.sigyn.toml` to inject secrets only into the processes that need them.
3. For maximum isolation, use `sigyn run serve` — secrets are accessible only via the Unix socket.
4. Run your AI coding agent in a separate terminal from your application.

### What Sigyn does NOT protect against

- An AI agent that has been explicitly granted access to run `sigyn` commands (e.g., `sigyn secret get`)
- Secrets that your application logs to stdout/stderr (visible if the agent reads log files)
- Secrets embedded in source code (use Sigyn instead of hardcoding)

## Threat Model Summary

| Threat | Mitigation |
|---|---|
| Stolen vault files | ChaCha20-Poly1305 encryption; attacker needs a member's private key |
| Compromised member | Revoke member; affected environment keys are rotated; cascade revocation removes their delegates |
| Tampered audit log | Hash chain breaks on tamper; Ed25519 signatures prove authorship |
| Tampered config/manifest | AEAD authentication; device key or master key required to forge |
| Tampered members.cbor | Ed25519 signature over content + vault_id; forgery requires signing key |
| Downgrade to plaintext | No fallbacks; all readers reject data without correct magic header |
| Forged MFA session | Session HMAC uses device-key-derived secret, not public fingerprint |
| Tampered invitation | Acceptance requires inviter's identity for signature verification |
| Lost access (key loss) | Shamir K-of-N recovery shards |
| Unauthorized access escalation | `PolicyEngine::evaluate()` on every operation; no bypass path |
| Brute-force passphrase | Argon2id with tuned memory/time cost |
| Stolen credentials (passphrase only) | Optional TOTP-based MFA as second factor; session grace period limits exposure window |
| AI agent reads env vars | `sigyn run exec` injects into child only; `sigyn run serve` uses Unix socket with no env exposure |
| Replay of old ciphertext | Unique nonces per encryption; vault UUID bound into HKDF salt |
| Sensitive data in memory | `secrecy::Secret` + `zeroize` on drop; constant-time fingerprint comparison |
| Partial file writes | Atomic writes via `tempfile::persist()` |
| Symlink traversal | Per-component symlink check rejects any symlink in path (parent dirs included) |
| Local filesystem snooping | `~/.sigyn/` directory `0o700`; all files `0o600`; all contents encrypted |
| Device key compromise | Limits exposure to Tier A files only; vault secrets require identity key |
| Rollback attack (force-push) | Commit OID checkpoints; descendant verification on pull |
| Copy-and-rehost attack | TOFU vault origin pinning; owner fingerprint checked on every unlock |
| Auditor privilege escalation | Optional split-repo layout; separate git permissions for vault and audit data |
| Org link metadata leak | `.org_link` encrypted with device key |
| MFA file swapping between identities | Fingerprint bound as AAD in AEAD encryption |
| Invitation replay/theft | 7-day expiry; Ed25519 signature with length-prefixed payload |
| Signing payload field confusion | Length-prefixed v2 format prevents boundary ambiguity |
| Hierarchy node header forgery | SGSN signed format with Ed25519 verification |
| Forged org/fork policy file | All policy files signed and bound to vault/node UUID; unsigned rejected |
| Crash during audit append | Trailing corrupt line tolerated; mid-file tampering detected |
| File permission TOCTOU | Atomic temp+rename with `0o600` mode set at creation |
| Predictable temp file attack | Editor temp files use cryptographically random names via `tempfile` crate |
| Secret leaking via process list | Inline `{{KEY}}` substitution requires explicit `--allow-inline-secrets` flag |
| Secret leaking via rotation hooks | Hook secrets passed via stdin, not environment variables; avoids `/proc/<pid>/environ` visibility |
| Hook command injection | Hooks executed directly (no shell); shell metacharacters and path traversal rejected at save time |
| Unaudited secret access | `sigyn run exec/export/serve` and `sigyn secret list` generate audit entries |
| Malicious project config | Warning when `.sigyn.toml` is in a git-tracked directory; identity override requires `SIGYN_TRUST_PROJECT_CONFIG` |
| Vault key retained after revocation | Vault key rotated on member revocation; new key re-sealed to remaining members only |
| Agent socket hijacking | Session token required for CACHE command; socket ownership verified before connecting |
| Device key tampering | Stored with BLAKE3 integrity hash; tampered files rejected on load |
| Identity file tampering | BLAKE3 keyed MAC (using device key) appended and verified on every load |
| Weak KDF parameters | Argon2id parameters validated against minimums (m\_cost >= 64 MiB, t\_cost >= 3, p\_cost >= 1) |
| Audit log gap injection | Sequence continuity verified — gaps in sequence numbers detected and rejected |
| Unsigned witness log | Witness log optionally signed with Ed25519; signature verified on load when verifying key available |
| Force-push on sync push | Push verifies local HEAD descends from remote HEAD; non-fast-forward rejected unless `--force` |
| TOFU pin poisoning on first access | Prominent warning banner on first vault access; `SIGYN_VERIFY_OWNER` env var for automated verification |
| Malicious EDITOR env var | Warning emitted when `$EDITOR`/`$VISUAL` points outside standard system paths |
| Rollback via malformed checkpoint | Invalid checkpoint OIDs produce an error instead of silently skipping validation |
| Cloud import argument injection | Cloud resource names validated: no leading dashes, control chars, or shell metacharacters |
| Generated secret leaking to stdout | `secret generate` hides value by default; requires `--reveal` flag |
| Passphrase lingering in memory | Passphrase strings zeroized at CLI call sites after use |

## Related Documentation

- [Architecture](architecture.md) -- project structure and module overview
- [CLI Reference](cli-reference.md) -- complete command reference
- [Delegation](delegation.md) -- invitation and revocation deep dive
- [Sync](sync.md) -- synchronization and conflict resolution
