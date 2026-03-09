# Delegation

This document describes how Sigyn manages vault membership through a delegation tree,
including invitation creation, acceptance, role constraints, cascade revocation, and
per-environment key rotation.

## Overview

Sigyn uses a delegation tree to track how members were added to a vault. Every member
(except the Owner) has a `delegated_by` field pointing to the fingerprint of the person
who invited them. This creates a tree rooted at the vault Owner.

Three governing principles:

1. **Least privilege**: members can only grant roles at or below their own level.
2. **Traceability**: every delegation is recorded, forming an auditable tree.
3. **Secure revocation**: removing a member cascades to their entire subtree and triggers per-environment key rotation for affected environments.

```
Owner (alice)
  |-- Admin (bob)         delegated_by: alice
  |     |-- Contributor (carol)   delegated_by: bob
  |     |-- ReadOnly (dave)       delegated_by: bob
  |-- Manager (eve)       delegated_by: alice
        |-- Operator (frank)      delegated_by: eve
```

## Invitation Flow

### Step 1: Create an Invitation

A member with the Manager role or higher can create an invitation. The inviter can
only assign a role **strictly below** their own level (e.g., a Manager can invite
Contributors but not other Managers or Admins). The Owner can invite any role except
Owner. The invitation is an `InvitationFile` -- a JSON document signed with the
inviter's Ed25519 key.

```bash
sigyn delegation invite create --role contributor --envs dev,staging
```

The invitation file contains:

| Field | Description |
|---|---|
| `id` | Unique UUID for this invitation |
| `vault_name` | Name of the vault being shared |
| `vault_id` | UUID of the vault |
| `inviter_fingerprint` | BLAKE3 fingerprint of the inviter |
| `proposed_role` | Role offered to the invitee |
| `allowed_envs` | Environments the invitee will have access to |
| `signature` | Ed25519 signature over the canonical payload |
| `created_at` | UTC timestamp |

Example invitation file:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "vault_name": "myapp",
  "vault_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "inviter_fingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "proposed_role": "contributor",
  "allowed_envs": ["dev", "staging"],
  "secret_patterns": ["*"],
  "max_delegation_depth": 0,
  "signature": "<Ed25519 signature bytes>",
  "created_at": "2026-02-23T10:30:00Z"
}
```

### Signing Payload

The Ed25519 signature covers a versioned, deterministic concatenation of fields:

```
"sigyn-invitation-v1:" || id || vault_name || vault_id || inviter_fingerprint || role_string || env1 || env2 || ...
```

This is constructed by `InvitationFile::signing_payload()` and prevents field
reordering or modification attacks.

### Step 2: Out-of-Band Sharing

The invitation file is shared with the invitee through any channel: email, chat,
file transfer, USB drive, etc. The file does not contain any secret key material.
It is safe to transmit over insecure channels -- the Ed25519 signature ensures the
invitee can verify it was created by a legitimate vault member.

### Step 3: Accept the Invitation

The invitee clones the vault and accepts the invitation on their machine:

```bash
# Single command (clone + accept):
sigyn vault clone git@github.com:team/secrets.git --invitation ./invitation-abc123.json

# Or separately:
sigyn vault clone git@github.com:team/secrets.git
sigyn delegation invite accept ./invitation-abc123.json
```

During acceptance:

1. **Signature verification**: the invitation's Ed25519 signature is verified against the inviter's public key via `InvitationFile::verify()`. If invalid, acceptance is rejected.
2. **Role validation**: the system confirms the inviter has sufficient privileges to delegate the proposed role.
3. **Envelope update**: the invitee's X25519 public key is registered in the vault's `EnvelopeHeader`. A `vault_key_slot` is created (encrypting the vault key via X25519 ECDH + HKDF + ChaCha20-Poly1305), and `env_slots` are created for each environment in the invitee's `allowed_envs` list, each encrypting that environment's independent key.
4. **Policy update**: a `MemberPolicy` entry is created with the proposed role, allowed environments, and `delegated_by` set to the inviter's fingerprint.
5. **Audit entry**: the acceptance is recorded in the hash-chained audit log.

### Invitation Lifecycle

Invitations have the following statuses:

| Status | Meaning |
|---|---|
| `Pending` | Created but not yet accepted |
| `Accepted` | Successfully accepted by the invitee |
| `Rejected` | Declined by the invitee |
| `Expired` | Past the `expires_at` timestamp |
| `Revoked` | Canceled by the inviter before acceptance |

List pending invitations:

```bash
sigyn delegation pending
```

## Role Constraints

A member can only delegate a role at or below their own level. The role hierarchy
(from lowest to highest):

| Level | Role | Can Delegate? |
|---|---|---|
| 1 | ReadOnly | No |
| 2 | Auditor | No |
| 3 | Operator | No |
| 4 | Contributor | No |
| 5 | Manager | Yes (roles 1--5) |
| 6 | Admin | Yes (roles 1--6) |
| 7 | Owner | Yes (roles 1--7) |

Only Manager (level 5) and above can delegate. This is enforced by
`Role::can_delegate()` which returns `true` only for `Role >= Manager`.

Examples:

- A **Manager** can invite someone as Manager, Contributor, Operator, Auditor, or ReadOnly.
- A **Manager** cannot invite someone as Admin or Owner.
- A **Contributor** cannot invite anyone, because delegation requires Manager or higher.
- An **Admin** can invite other Admins, Managers, and all lower roles.

Environment and secret pattern restrictions are also inherited: a delegator cannot
grant access to environments or patterns they do not have access to themselves.

## Delegation Tree

The delegation tree is represented by `DelegationNode`:

```rust
DelegationNode {
    fingerprint: KeyFingerprint,
    name: String,
    role: Role,
    depth: u32,
    delegated_by: Option<KeyFingerprint>,
    children: Vec<DelegationNode>,
}
```

The tree is constructed by walking all `MemberPolicy` entries and linking each member
to their `delegated_by` parent. The `display_tree()` method renders it with indentation.

View the tree:

```bash
sigyn delegation tree
```

Output:

```
alice (a1b2c3d4e5f6a7b8) [owner]
  bob (e5f6a7b8c9d0e1f2) [admin]
    carol (c9d0e1f2a3b4c5d6) [contributor]
    dave (1a2b3c4de7f8a9b0) [readonly]
  eve (5e6f7a8bc9d0e1f2) [manager]
    frank (9c0d1e2fa3b4c5d6) [operator]
```

## Cascade Revocation

When a member is revoked with `--cascade`, Sigyn removes the target and all members
they transitively invited. This is implemented as a BFS (breadth-first search)
traversal of the delegation tree in `collect_cascade()`.

### Algorithm

```
function collect_cascade(root, policy):
    revoked = []
    queue = [root]
    while queue is not empty:
        parent = queue.pop()
        for member in policy.members:
            if member.delegated_by == parent and member not in revoked:
                revoked.append(member)
                queue.append(member)
    return revoked
```

### Example

Given the tree:

```
alice [owner]
  bob [admin]
    carol [contributor]
    dave [readonly]
  eve [manager]
```

Revoking **bob** with `--cascade`:

1. BFS starts from bob.
2. Finds carol (delegated_by: bob) -- added to revoked set.
3. Finds dave (delegated_by: bob) -- added to revoked set.
4. Checks carol's children -- none.
5. Checks dave's children -- none.
6. Result: bob, carol, and dave are all revoked. Eve is unaffected.

```bash
sigyn delegation revoke <bob-fingerprint> --cascade
```

After revocation:

```
alice [owner]
  eve [manager]
```

### Without Cascade

Revoking **bob** without `--cascade` removes only bob from the policy. Carol and dave
remain as members but their `delegated_by` still points to the now-removed bob. This
is useful when you want to remove a specific member without disrupting their delegates.

```bash
sigyn delegation revoke <bob-fingerprint>
```

## Per-Environment Key Rotation on Revoke

Every revocation triggers key rotation for the affected environments. This is a
critical security property: it ensures revoked members can no longer decrypt any
vault data they previously had access to, even if they retained a copy of the
encrypted files.

### Rotation Process

1. The `revoke_member_v2()` function builds the full list of fingerprints to remove (target + cascade, if applicable).
2. All affected members are removed from the `VaultPolicy`.
3. The revoked members' `vault_key_slots` and `env_slots` are removed from the `EnvelopeHeader`.
4. For each environment the revoked members had access to, a new 256-bit environment key is generated and sealed to the remaining authorized members.
5. Only the affected environment files are re-encrypted with their new keys. **Unaffected environments are untouched** -- this is a key benefit of per-environment key isolation.
6. The updated `EnvelopeHeader` and `VaultPolicy` are persisted atomically.

### RevocationResult

The `revoke_member_v2()` function returns:

```rust
RevocationResultV2 {
    directly_revoked: KeyFingerprint,                 // The target member
    cascade_revoked: Vec<KeyFingerprint>,             // Transitively revoked delegates
    new_vault_cipher: Option<VaultCipher>,            // Rotated vault cipher (if applicable)
    rotated_env_ciphers: BTreeMap<String, VaultCipher>, // New ciphers per affected env
    affected_envs: Vec<String>,                       // Environments that were re-keyed
}
```

Only environments the revoked members had access to are re-keyed. For example,
revoking a member with `allowed_envs: ["dev", "staging"]` rotates only the dev
and staging keys -- the prod key and env file are untouched.

### Per-Environment Access Management

Beyond full revocation, individual environment access can be adjusted:

```bash
# Grant a member access to an additional environment
sigyn delegation grant-env <fingerprint> staging

# Revoke a member's access to a specific environment (rotates that env key)
sigyn delegation revoke-env <fingerprint> staging
```

`revoke-env` removes the member's slot for that environment, rotates the environment
key, and re-encrypts the environment file -- without affecting other environments
or other members' access.

## Constraints on Delegated Access

Beyond role level, delegated members can have constraints that are checked by
`PolicyEngine::evaluate()` on every access:

### Time Windows

Restrict access to specific days and hours. Supports overnight ranges (e.g.,
`start_hour: 22, end_hour: 6`).

```rust
TimeWindow {
    days: [Mon, Tue, Wed, Thu, Fri],
    start_hour: 9,
    end_hour: 17,
}
```

### Expiry

Members can have an `expires_at` timestamp. After expiry, all access is denied
regardless of role.

### Environment Restrictions

Members are limited to the environments specified in their `allowed_envs` list. A
wildcard `*` grants access to all environments.

### Secret Patterns

Members can be restricted to secrets matching specific glob patterns (e.g., `DB_*`,
`REDIS_*`). The key is matched against the member's `secret_patterns` list via
`matches_secret_pattern()`.

## Breach Mode

In an emergency, breach mode provides a one-command response that revokes all
delegated members and rotates all keys:

```bash
sigyn rotate breach-mode
```

This:

1. Rotates the vault key and re-encrypts vault-level metadata (manifest, policy, audit).
2. Rotates every per-environment key and re-encrypts every environment file.
3. Rotates every secret in every environment to a new random value.
4. Removes all delegated members from all slots.
5. Saves the updated policy.
6. Logs an audit entry for the breach mode activation.

Only members with Admin role or higher can activate breach mode
(`AccessAction::ManagePolicy` is required).

## Bulk Operations

For onboarding or offboarding multiple team members at once, use the bulk commands:

### Bulk Invite

```bash
sigyn delegation bulk-invite --file members.json
```

The JSON file contains an array of member definitions:

```json
[
  {"fingerprint": "a1b2c3d4e5f6...", "role": "contributor", "envs": "dev,staging"},
  {"fingerprint": "f7e8d9c0b1a2...", "role": "readonly", "envs": "*"}
]
```

All entries are validated before any are applied. If any fingerprint is invalid or any
role is unrecognized, the entire operation is aborted. On success, the header and policy
are saved once (not per entry), and each member gets an audit entry.

### Bulk Revoke

```bash
sigyn delegation bulk-revoke --file revoke-list.json --cascade
```

The JSON file is a simple array of fingerprint strings:

```json
["a1b2c3d4e5f6...", "f7e8d9c0b1a2..."]
```

Uses the same revocation logic as `delegation revoke`, including key rotation and
optional cascade. All fingerprints are validated before any mutations.

## Ownership Transfer

Vault ownership can be transferred to another member using a two-phase protocol:

```bash
# Phase 1: Current owner initiates transfer
sigyn vault transfer myapp --to a1b2c3d4e5f6...

# Phase 2: New owner accepts and re-signs
sigyn vault accept-transfer myapp
```

Phase 1 only writes a signed `pending_transfer.cbor` — the old owner retains full
control until the new owner accepts. Phase 2 atomically updates the manifest, policy,
and header. The old owner is downgraded to Admin by default (configurable with
`--downgrade-to`). Transfers expire after 7 days. Both phases are recorded in the
audit trail.

## Operational Recommendations

1. **Use cascade revocation** when removing someone who has invited others, unless you specifically want to preserve their subtree.
2. **Set expiry on contractor access** to ensure temporary members lose access automatically.
3. **Use time windows for CI/CD** to limit automated access to deployment hours.
4. **Audit the delegation tree regularly** with `sigyn delegation tree` to understand the access structure.
5. **Prefer Contributor over Admin** when in doubt. Follow the principle of least privilege.
6. **Set up Shamir recovery shards** before distributing vault access widely, so that key loss does not lock out the entire team.

## Related Documentation

- [Security Model](security.md) -- RBAC, policy engine, and constraints
- [CLI Reference](cli-reference.md) -- complete command reference for delegation commands
- [Sync](sync.md) -- how delegation changes are synchronized
- [Architecture](architecture.md) -- module structure for delegation code
