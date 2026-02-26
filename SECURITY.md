# Security

For the full security model, see [docs-site/src/security.md](docs-site/src/security.md).

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately. Do **not**
open a public GitHub issue.

## Security Hardening Summary

The following hardening measures protect against insider threats — a legitimate
vault member who attempts to escalate privileges, tamper with audit trails, or
retain access after revocation.

### Policy Integrity

- **Owner-key verification**: vault policy signatures are verified against the
  vault owner's signing key (from TOFU pin), not the current user's key. This
  prevents a non-owner member from forging policy changes.
- **No silent fallback**: policy load failures produce explicit warnings instead
  of silently returning an empty (permissive) policy.

### Revocation

- **Vault key rotation**: the vault-level encryption key is rotated immediately
  when a member is revoked. A new key is generated and re-sealed to remaining
  members only. The revoked member's cached key becomes useless.
- **Per-environment key rotation**: environment keys the revoked member had
  access to are also rotated independently.
- **Cascade revocation**: revoking a member also revokes everyone they invited,
  transitively.

### Rotation Hooks

- **Direct execution**: hooks are spawned directly (`Command::new`), never via
  `sh -c`. Shell metacharacters are rejected at save time.
- **Stdin secret delivery**: the rotated secret is passed to hooks via stdin,
  not environment variables, preventing visibility in `/proc/<pid>/environ`.
- **Validation**: hook commands are validated for shell metacharacters, path
  traversal, and length limits when saved to policy.

### Passphrase Agent

- **Session token**: the `CACHE` command requires a random session token
  generated at daemon start. Only processes that received the token (same user)
  can cache passphrases.
- **Socket ownership**: before connecting, the client verifies the socket file
  is owned by the current UID.
- **XDG_RUNTIME_DIR**: the agent socket directory prefers `XDG_RUNTIME_DIR`
  (already user-owned, `0o700`). Fallback uses restrictive umask for atomic
  directory creation.

### Audit Trail

- **Signature enforcement**: `sigyn audit verify` verifies Ed25519 signatures
  against actor public keys from vault policy. Entries by unknown actors are
  rejected.
- **Gap detection**: sequence continuity is verified — gaps in sequence numbers
  (from selective deletion) are detected and reported.
- **Witness log signing**: witness logs use a signed format
  (`SGNW || signature || ciphertext`) verified on load.
- **Run command auditing**: `sigyn run exec`, `sigyn run export`,
  `sigyn run serve`, and `sigyn secret list` all generate audit entries.

### Identity and Device Key Integrity

- **Device key hash**: stored as `key(32) || BLAKE3(key || context)(32)`.
  Verified on every load; tampered files are rejected.
- **Identity file MAC**: a BLAKE3 keyed MAC (using the device key) is appended
  to identity files and verified on every load.
- **KDF parameter validation**: Argon2id parameters are validated against
  minimum thresholds (`m_cost >= 64 MiB`, `t_cost >= 3`, `p_cost >= 1`).
  Identity files with weakened parameters are rejected.

### TOFU Pinning

- **First-access warning**: a prominent banner is displayed on first vault
  access, urging out-of-band verification of the owner fingerprint.
- **Automated verification**: `SIGYN_VERIFY_OWNER=<fingerprint>` can be set to
  require a match before the TOFU pin is saved.

### Git and Sync

- **Push-side force-push detection**: `sigyn sync push` verifies that the local
  HEAD descends from the remote HEAD before pushing. Non-fast-forward pushes are
  rejected unless `--force` is explicitly passed.
- **Pull-side rollback detection**: commit OID checkpoints detect forced remote
  history rewrites.

### Project Config Trust

- **Git-tracked warning**: `.sigyn.toml` loaded from a git-tracked directory
  triggers a warning to verify the file was not modified by an untrusted party.
- **Identity override protection**: the `identity` field in `.sigyn.toml`
  requires `SIGYN_TRUST_PROJECT_CONFIG` to take effect. Without it, the override
  is ignored with a warning.

### Filesystem

- **Symlink protection**: vault paths are checked for symlinks at every
  component before any file I/O, preventing symlink-based redirection attacks.
- **Atomic writes**: all file writes use temp-file-and-rename with `0o600`
  permissions set at creation, eliminating TOCTOU windows.

### Process Isolation

- **`/proc` visibility warning**: when `SIGYN_VERBOSE` is set, `sigyn run exec`
  warns that secrets in environment variables may be visible via
  `/proc/<pid>/environ` to the same UID.

### Delegation Chain Integrity

- **Delegator verification**: when validating a delegation, if the inviter was
  themselves delegated, Sigyn verifies the delegator still exists in the vault
  policy. This prevents a revoked intermediary's invitations from remaining valid.
