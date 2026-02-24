# Organizations

This document describes how Sigyn organizes vaults into hierarchical organizations,
including the on-disk layout, RBAC inheritance, cascading encryption, and git remote
inheritance.

## Overview

Organizations let you group vaults under a nested hierarchy of divisions, teams, and
other organizational units. Each node in the hierarchy carries its own encrypted RBAC
policy. Permissions cascade downward -- a member added at the top of the tree automatically
gains access to every child node and linked vault below.

Three governing principles:

1. **Highest role wins**: when a member appears at multiple levels, the highest role is
   used for access decisions.
2. **Permission union**: allowed environments and secret patterns are unioned across all
   levels in the chain.
3. **Encryption per node**: each hierarchy node has its own envelope header and encrypted
   policy, so a compromise at one level does not expose sibling branches.

## On-Disk Layout

Organizations live under `~/.sigyn/orgs/`. Each node is a directory containing a manifest,
encrypted policy, and envelope header:

```
~/.sigyn/orgs/
  └── acme/                          # root org (node_type: "org")
      ├── node.toml                  # NodeManifest (metadata, owner, children)
      ├── members.cbor               # Envelope header (sealed master key slots)
      ├── policy.cbor                # Encrypted VaultPolicy (RBAC)
      └── children/
          └── platform/              # child node (node_type: "division")
              ├── node.toml
              ├── members.cbor
              ├── policy.cbor
              └── children/
                  └── web/           # grandchild (node_type: "team")
                      ├── node.toml
                      ├── members.cbor
                      └── policy.cbor
```

### NodeManifest (`node.toml`)

Each node's manifest contains:

| Field | Description |
|---|---|
| `node_id` | Unique UUID |
| `name` | Human-readable node name |
| `node_type` | Node kind: `org`, `division`, `team`, or any custom string |
| `parent_id` | UUID of the parent node (`None` for root orgs) |
| `owner` | BLAKE3 fingerprint of the node creator |
| `children` | List of `ChildRef` entries (id, name, type) |
| `created_at` | UTC creation timestamp |
| `description` | Optional description |
| `git_remote` | Optional `GitRemoteConfig` (url, branch) |

### Vault Linking

Vaults are linked to org nodes via their `VaultManifest`. When a vault is attached
to an org path, its `org_path` field is set (e.g., `"acme/platform/web"`). The vault
files remain in `~/.sigyn/vaults/` -- only the metadata link changes.

## Creating Organizations

### Create a root org

```bash
sigyn org create acme
```

Creates `~/.sigyn/orgs/acme/` with a `node.toml` (type `org`), sealed `members.cbor`,
and encrypted `policy.cbor`. The caller becomes the owner.

### Add child nodes

```bash
sigyn org node create platform --parent acme --type division
sigyn org node create web --parent acme/platform --type team
```

| Flag | Description |
|---|---|
| `--parent <PATH>` | Parent org path (e.g., `acme` or `acme/platform`) |
| `--type <TYPE>` | Node type string (default: `team`) |

### Remove a node

```bash
sigyn org node remove acme/platform/web
```

Only empty nodes (no children, no linked vaults) can be removed.

## Linking Vaults to Organizations

### Create a vault under an org

```bash
sigyn vault create myapp --org acme/platform/web
```

Creates the vault and immediately sets its `org_path` to the given path.

### Attach an existing vault

```bash
sigyn vault attach legacy-app --org acme
```

Sets the vault's `org_path` field. The vault must not already be linked to another org.

### Detach a vault

```bash
sigyn vault detach legacy-app
```

Clears the vault's `org_path` field, removing it from the hierarchy.

## Viewing the Hierarchy

### Tree view

```bash
sigyn org tree
sigyn org tree --org acme
```

Displays the full org hierarchy with node types:

```
acme (org)
  └── platform (division)
      └── web (team)
```

### Node info

```bash
sigyn org info acme/platform/web
```

Shows node metadata: UUID, type, owner, children, creation date, linked vaults,
and git remote configuration.

## RBAC at the Org Level

Each hierarchy node has its own encrypted `VaultPolicy`. Members can be added,
removed, and inspected at any level.

### Add a member

```bash
sigyn org policy member-add <fingerprint> --role admin --path acme
sigyn org policy member-add <fingerprint> --role contributor --path acme/platform/web
```

| Flag | Description |
|---|---|
| `--role <ROLE>` | Role to assign: `readonly`, `auditor`, `operator`, `contributor`, `manager`, `admin`, `owner` |
| `--path <PATH>` | Org path where the membership applies |

### Remove a member

```bash
sigyn org policy member-remove <fingerprint> --path acme
```

### Show policy

```bash
sigyn org policy show --path acme
sigyn org policy show --path acme/platform/web
```

Displays all members at that node: fingerprint, role, allowed environments, and
secret patterns.

### Check effective permissions

```bash
sigyn org policy effective <fingerprint> --path acme/platform/web
```

Computes the merged permissions by walking the chain from the target node up to
the root org, then displays the effective role, environments, and patterns.

## Inherited Permissions

When Sigyn evaluates access for a member at a given node, it builds a policy chain
from the target node up through every ancestor to the root org. The merge rules are:

### Highest role wins

If a member is `ReadOnly` at `acme/platform/web` but `Admin` at `acme`, their
effective role is `Admin`.

```
Role levels (highest wins):
  1 ReadOnly
  2 Auditor
  3 Operator
  4 Contributor
  5 Manager
  6 Admin
  7 Owner
```

### Environment union

Allowed environments from all levels are combined. If any level grants `*` (all
environments), the result is `*`.

| Level | Envs | Merged |
|---|---|---|
| `acme` | `staging, prod` | |
| `acme/platform` | -- | |
| `acme/platform/web` | `dev` | `dev, staging, prod` |

### Pattern union

Secret patterns from all levels are combined with the same logic. If any level
grants `*`, the result is `*`.

### Owner at any level

If a member is the owner at any node in the chain, they are granted full access
immediately -- no further checks are performed.

## Cascading Encryption

Each hierarchy node has its own `members.cbor` (envelope header) and `policy.cbor`.
When a member is added at a node, a sealed slot is created for that node's master
key. This means:

- Adding a member at `acme` gives them a key slot for the `acme` node only.
- The member must also have slots at child nodes to decrypt those policies.
- The `org policy member-add` command handles slot creation at the target level.

When a member is removed, their slot is deleted and the node's master key is rotated,
just like vault-level revocation.

## Git Remote Inheritance

Each node can optionally have a `GitRemoteConfig` (url + branch). When Sigyn needs
the git remote for a node, it walks up the hierarchy from the target node to the root
and uses the **first** non-empty remote it finds.

```bash
# Set a remote at the org level
sigyn org sync configure --path acme \
  --remote-url git@github.com:acme/secrets.git

# Override at a child node
sigyn org sync configure --path acme/platform/web \
  --remote-url git@github.com:acme/web-secrets.git \
  --branch develop
```

| Flag | Description |
|---|---|
| `--path <PATH>` | Org path to configure |
| `--remote-url <URL>` | Git remote URL |
| `--branch <NAME>` | Branch name (default: `main`) |

Child nodes without an explicit remote inherit from their nearest ancestor that has
one configured.

## Worked Example

A complete walkthrough for setting up an organization:

```bash
# 1. Create identities
sigyn identity create -n alice
sigyn identity create -n bob

# 2. Create the org hierarchy
sigyn org create acme
sigyn org node create platform --parent acme --type division
sigyn org node create web --parent acme/platform --type team
sigyn org node create mobile --parent acme/platform --type team

# 3. Create vaults under the hierarchy
sigyn vault create webapp --org acme/platform/web
sigyn vault create ios-app --org acme/platform/mobile

# 4. Attach an existing vault
sigyn vault create shared-infra
sigyn vault attach shared-infra --org acme

# 5. Configure git sync at the org level (inherited by children)
sigyn org sync configure --path acme \
  --remote-url git@github.com:acme-corp/secrets.git

# 6. Add an org-wide admin (inherits access to all children and vaults)
sigyn org policy member-add <bob-fingerprint> --role admin --path acme

# 7. Add a team-level contributor
sigyn org policy member-add <carol-fingerprint> --role contributor \
  --path acme/platform/web

# 8. Check Bob's effective permissions at the web team level
sigyn org policy effective <bob-fingerprint> --path acme/platform/web
#   -> Role: Admin (inherited from acme)
#   -> Envs: * (inherited)
#   -> Patterns: * (inherited)

# 9. View the full hierarchy
sigyn org tree
#   acme (org)
#     └── platform (division)
#         ├── web (team)
#         └── mobile (team)

# 10. Detach a vault if needed
sigyn vault detach shared-infra
```

## Commands Summary

| Command | Description |
|---|---|
| `org create <name>` | Create a root organization |
| `org node create <name> --parent <path>` | Add a child node |
| `org node remove <path>` | Remove an empty node |
| `org tree [--org <name>]` | Display hierarchy tree |
| `org info <path>` | Show node details |
| `org policy show --path <path>` | Show RBAC at a node |
| `org policy member-add <fp> --role <role> --path <path>` | Add member at node |
| `org policy member-remove <fp> --path <path>` | Remove member from node |
| `org policy effective <fp> --path <path>` | Show merged effective permissions |
| `org sync configure --path <path> --remote-url <url>` | Set git remote for node |
| `vault create <name> --org <path>` | Create vault linked to org |
| `vault attach <name> --org <path>` | Link existing vault to org |
| `vault detach <name>` | Unlink vault from org |

## Related Documentation

- [Delegation](delegation.md) -- invitation and revocation system
- [Sync](sync.md) -- git-based synchronization
- [Security Model](security.md) -- encryption and access control
- [CLI Reference](cli-reference.md) -- complete command reference
