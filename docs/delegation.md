# Delegation and Invitation System

This document provides a deep dive into how Sigyn manages team access through
delegation trees, signed invitations, and cascade revocation.

## Overview

Sigyn's delegation system is built around three principles:

1. **Least privilege**: members can only grant roles at or below their own level.
2. **Traceability**: every delegation is recorded, forming a tree rooted at the vault owner.
3. **Secure revocation**: removing a member cascades to their entire subtree and triggers master key rotation.

## Invitation Flow

### Step 1: Create an Invitation

A Manager, Admin, or Owner creates an invitation file specifying the invitee's
public key fingerprint, proposed role, and allowed environments:

```bash
sigyn delegation invite create \
  --pubkey e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 \
  --role contributor \
  --env dev,staging
```

This produces a JSON invitation file with the following structure:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "vault_name": "myapp",
  "vault_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "inviter_fingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "proposed_role": "contributor",
  "allowed_envs": ["dev", "staging"],
  "signature": "<Ed25519 signature bytes>",
  "created_at": "2025-03-15T10:30:00Z"
}
```

The invitation is signed with the inviter's Ed25519 key over a deterministic payload
consisting of: `id || vault_name || vault_id || inviter_fingerprint || role || envs`.
This prevents tampering with any field of the invitation.

### Step 2: Share Out-of-Band

The invitation file is shared with the invitee through any channel: email, encrypted
chat, file transfer, USB drive, etc. The file contains no secret material -- it is
a signed offer of access, not the access itself.

### Step 3: Accept the Invitation

The invitee runs:

```bash
sigyn delegation invite accept invitation-abc123.json
```

Acceptance performs the following:

1. **Signature verification**: the invitation's Ed25519 signature is verified against
   the inviter's public key. If the signature is invalid, acceptance is rejected.
2. **Role validation**: the system confirms the inviter has sufficient privileges to
   delegate the proposed role.
3. **Envelope update**: the invitee's X25519 public key is added as a new slot in
   the vault's envelope header, allowing them to decrypt the master key.
4. **Policy update**: a new `MemberPolicy` entry is created with the specified role,
   allowed environments, and a `delegated_by` pointer to the inviter's fingerprint.
5. **Audit entry**: the acceptance is recorded in the audit log.

### Invitation Statuses

| Status | Description |
|---|---|
| Pending | Created but not yet accepted |
| Accepted | Successfully accepted by the invitee |
| Rejected | Explicitly rejected by the invitee |
| Expired | Past the expiration time (if set) |
| Revoked | Cancelled by the inviter before acceptance |

## Role Constraints

A member can only delegate roles at or below their own level. The role hierarchy
(from [Security Model](security.md)):

| Level | Role | Can Delegate? |
|---|---|---|
| 1 | ReadOnly | No |
| 2 | Auditor | No |
| 3 | Operator | No |
| 4 | Contributor | No |
| 5 | Manager | Yes (roles 1-5) |
| 6 | Admin | Yes (roles 1-6) |
| 7 | Owner | Yes (roles 1-7) |

Only Manager and above can delegate. A Manager can invite Contributors, Operators,
Auditors, ReadOnly members, and other Managers. An Admin can also invite other Admins.
Only the Owner can invite Admins with full policy management rights.

## Delegation Tree

Every member (except the Owner) has a `delegated_by` field pointing to the fingerprint
of the member who invited them. This forms a tree:

```
Owner (alice)
  |
  +-- Admin (bob)          [delegated_by: alice]
  |     |
  |     +-- Contributor (carol)  [delegated_by: bob]
  |     +-- ReadOnly (dave)      [delegated_by: bob]
  |
  +-- Manager (eve)        [delegated_by: alice]
        |
        +-- Contributor (frank)  [delegated_by: eve]
```

The tree structure is stored in the vault's policy file (`policy.cbor`). Each
`MemberPolicy` entry contains:

```rust
pub struct DelegationNode {
    pub fingerprint: KeyFingerprint,
    pub name: String,
    pub role: Role,
    pub depth: u32,
    pub delegated_by: Option<KeyFingerprint>,
    pub children: Vec<DelegationNode>,
}
```

View the tree:

```bash
sigyn delegation tree
```

Output:

```
alice (a1b2c3d4...) [owner]
  bob (e5f6a7b8...) [admin]
    carol (c9d0e1f2...) [contributor]
    dave (1a2b3c4d...) [readonly]
  eve (5e6f7a8b...) [manager]
    frank (9c0d1e2f...) [contributor]
```

## Cascade Revocation

When a member is revoked with `--cascade`, all members they directly or transitively
invited are also revoked. The traversal uses BFS (breadth-first search):

```bash
sigyn delegation revoke --fingerprint e5f6a7b8... --cascade
```

### Algorithm

Given the target fingerprint to revoke:

1. Initialize a queue with the target fingerprint.
2. While the queue is not empty:
   a. Pop a fingerprint from the queue.
   b. Find all members whose `delegated_by` matches this fingerprint.
   c. Add those members to the revocation list and to the queue.
3. Remove all collected fingerprints from the policy.

### Example

Revoking Bob (with cascade) from the tree above:

```
Before:                          After:
alice [owner]                    alice [owner]
  bob [admin]         <-- revoked
    carol [contributor]  <-- cascade revoked
    dave [readonly]      <-- cascade revoked
  eve [manager]                    eve [manager]
    frank [contributor]              frank [contributor]
```

Bob, Carol, and Dave are all removed. Eve and Frank are unaffected because they
were not in Bob's subtree.

### Without Cascade

If `--cascade` is not specified, only the target member is revoked. Their children
become orphans in the tree (still have access, but their `delegated_by` points to
a removed member). This is useful when you want to remove a specific person but
keep their invitees.

```bash
sigyn delegation revoke --fingerprint e5f6a7b8...
```

## Master Key Rotation on Revocation

Every revocation triggers a master key rotation:

1. A new random 256-bit master key is generated.
2. The new master key is sealed (envelope encrypted) to each remaining member's
   X25519 public key.
3. The old envelope header is replaced with the new one.
4. All vault data is re-encrypted with the new master key.

This ensures that revoked members -- even if they have a copy of the encrypted vault
files from before the revocation -- cannot decrypt any data encrypted after the
rotation.

The `RevocationResult` returned by the revocation operation:

```rust
pub struct RevocationResult {
    pub directly_revoked: KeyFingerprint,
    pub cascade_revoked: Vec<KeyFingerprint>,
    pub master_key_rotated: bool,  // always true
}
```

## Constraints on Delegated Access

When creating an invitation, the inviter can attach constraints that limit the
invitee's access beyond what their role would normally allow:

### Time Windows

Restrict access to specific days and hours:

```bash
sigyn delegation invite create \
  --pubkey <fp> \
  --role contributor \
  --env dev \
  --time-window "Mon-Fri 09:00-17:00 UTC"
```

### IP Allowlists

Restrict access to specific IP addresses or CIDR ranges:

```bash
sigyn delegation invite create \
  --pubkey <fp> \
  --role contributor \
  --env dev \
  --ip-allow "192.168.1.0/24,10.0.0.0/8"
```

### Expiry

Set an automatic expiration for the membership:

```bash
sigyn delegation invite create \
  --pubkey <fp> \
  --role contributor \
  --env dev \
  --expires "2025-12-31T23:59:59Z"
```

After expiry, the member's access is denied by the policy engine even though their
slot remains in the envelope header. The slot should be cleaned up by running
a rotation or explicit removal.

### Secret Patterns

Restrict which secrets the member can access using glob patterns:

```bash
sigyn delegation invite create \
  --pubkey <fp> \
  --role contributor \
  --env dev \
  --secret-patterns "DB_*,REDIS_*"
```

### MFA Requirement

Require multi-factor authentication for the member:

```bash
sigyn delegation invite create \
  --pubkey <fp> \
  --role contributor \
  --env prod \
  --require-mfa
```

All constraints are stored in the member's policy entry and checked by
`PolicyEngine::evaluate()` on every access. See [Security Model](security.md)
for details on how the policy engine works.

## Viewing Pending Invitations

List invitations that have been created but not yet accepted:

```bash
sigyn delegation pending
```

## Operational Recommendations

1. **Use cascade revocation** when removing someone who has invited others, unless
   you specifically want to preserve their subtree.

2. **Set expiry on contractor access** to ensure temporary members lose access
   automatically.

3. **Use time windows for CI/CD** to limit automated access to deployment hours.

4. **Audit the delegation tree regularly** with `sigyn delegation tree` to understand
   the access structure.

5. **Prefer Contributor over Admin** when in doubt. Follow the principle of least
   privilege.

## Related Documentation

- [Security Model](security.md) -- RBAC, policy engine, and constraints
- [CLI Reference](cli-reference.md) -- complete command reference for delegation commands
- [Sync](sync.md) -- how delegation changes are synchronized
- [Architecture](architecture.md) -- module structure for delegation code
