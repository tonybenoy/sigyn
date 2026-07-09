# Changelog

All notable changes to Sigyn are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.15.0] - 2026-07-09

Security hardening release. A full workspace security and code review surfaced a
set of trust-model, data-loss, and "reports success while doing nothing" bugs in
the layers above the (already sound) cryptographic core. This release fixes them.

### Security — access control & trust model

- **Policy signer trust anchor (critical).** A vault policy could previously
  vouch for its own signer: any member holding the vault key could rewrite the
  policy to grant themselves admin, sign it with their own (locally known) key,
  and have every other device accept it. Non-owner ("admin-signed") policies are
  now checked against a device-local trust anchor recorded from the last accepted
  policy (stored in the never-synced `pinned_vaults.cbor`), and an admin-signed
  policy may not add or elevate privileged members — only an owner-signed policy
  can change the admin set. Applied to both the CLI and the web GUI unlock paths.
- **Hierarchical RBAC no longer cross-multiplies grants.** Each org/vault level is
  now evaluated as an atomic (role, envs, patterns) grant; a capability granted
  narrowly at one level can no longer combine with scope granted only at another.
- **Org-policy signatures fail closed.** If an org node owner's verifying key
  can't be resolved from a pinned/local source, evaluation now fails instead of
  falling back to the requester's own key. Missing/corrupt org levels named by a
  vault's `org_path` are hard errors, not silently skipped.
- **Per-key ACLs enforced on bulk operations.** `key: None` requests (list
  `--reveal`, `run`, `export`, `import`, copy-source, TUI) now require unrestricted
  pattern access instead of skipping the per-key check entirely.
- **`policy member-add` / org `member-add`** reject `--role owner` and enforce the
  same "cannot grant a role ≥ your own" rule as `delegation invite`;
  `member-remove` now warns prominently that key slots are not rotated (use
  `delegation revoke`).
- **MFA session tokens are bound to the identity.** The session HMAC now mixes in
  the fingerprint, so a copied session file no longer validates for another
  identity. (Existing sessions are invalidated by this change and must be
  re-verified.)

### Security — data integrity & durability

- **`delegation revoke <fp1> <fp2>` no longer bricks the vault (critical).**
  Batch revocation now computes all key rotations in memory and persists the
  header, policy, and re-sealed data files from a single consistent state, so a
  multi-fingerprint revoke can no longer leave the members header and data files
  sealed under different keys. `MemberRevoked` audit entries are recorded under
  the rotated key instead of being silently dropped.
- **Audit tamper detection.** `sigyn audit verify` now exits non-zero on a broken
  chain or invalid signature (previously exited 0). Tail truncation is detected
  via a device-local audit tip recorded after each append and checked on verify.
  An entry whose signing key is merely unavailable locally is reported as
  unverifiable (a warning), not as tampering.
- **Vault write locking.** A real advisory file lock (`VaultLock`) is now held
  across the read-modify-write sequences in `secret set`/`remove`/`edit` and
  `delegation revoke`, preventing lost updates from concurrent processes.
- **Durable, atomic writes.** `atomic_write` now fsyncs the file and parent
  directory; sealed `members.cbor`/manifest writes in the hierarchy and fork
  paths go through it (temp-file + rename, `0o600`, symlink checks).
- **Identity file integrity.** A new-format identity blob with a bad MAC can no
  longer masquerade as the old format (trailing-byte check).

### Security — recovery, sync, MFA, web

- **Recovery actually completes.** `sigyn-recovery restore` writes the recovered
  identity directly into the identity store (`~/.sigyn/identities/<fp>.identity`,
  honoring `SIGYN_HOME`), prompting for a new passphrase, with an overwrite guard
  and an optional `--output` path. The old instruction pointed at a nonexistent
  `identity import` command.
- **Shamir reconstruction rejects bad shards.** Duplicate/zero share indices,
  `threshold == 0`, and inconsistent split metadata are rejected, and an
  authenticator detects an incorrect reconstruction instead of silently returning
  a wrong key.
- **Sync honesty.** A diverged pull is reported as a conflict requiring a merge
  (was reported as success); `sync resolve` fails with manual-resolution guidance
  instead of falsely printing "Resolved conflict"; `pull` refuses to overwrite
  uncommitted local changes; the force-push safety check is enforced on the
  deploy-key path.
- **Self-update integrity.** The release checksums are verified against a
  binary-pinned Ed25519 key (fail-closed until configured), and downloads are size
  capped while streaming instead of buffered unbounded.
- **Web GUI.** All routes reject non-loopback `Host` headers (DNS-rebinding
  defense); `/api/identities` returns only login-critical fields (name,
  fingerprint) unauthenticated and gates email behind a session; audit-log
  failures fail closed on write/delete; internal error details are no longer
  returned to the client.
- **Invitation timestamps are signed.** `created_at`/`expires_at` are now part of
  the signed invitation payload (format v3), so an invitee can no longer extend or
  remove the expiry. Pending pre-0.15 invitations must be re-issued.

### Fixed — robustness

- `from_hex` no longer panics on multi-byte UTF-8 input; `secret import` no longer
  panics on a lone-quote value; `secret edit` shreds its plaintext temp file on all
  exit paths; `mfa status` no longer panics on a corrupt device key.
- Rotation schedules validate their cron expression at construction; rotation hooks
  are validated (traversal/metacharacter/length) before being saved.
- `secret set`/`secret remove` and batch `delegation revoke` return a non-zero exit
  code when any item fails.
- Key names reject `..` path-traversal components, leading/empty path segments, and
  NUL bytes. The agent socket is created with a restrictive umask.
- Vector-clock comparison treats an explicit zero entry as absent; fork-approval
  rejections are terminal and self-approval is refused.

### Changed

- `SIGYN_MFA_CODE` is honored for scripted MFA; MFA code prompts no longer consume
  `SIGYN_PASSPHRASE`.
- `is_interactive()` now requires both stdin and stderr to be terminals.
- Vault-default resolution across `delegation` and `sync` uses the configured
  `default_vault` instead of the literal `"default"`.
- Dependencies updated to their latest semver-compatible versions.

### Internal / refactors

- The policy-signer trust-anchor decision (finding C1) is now a single shared
  routine in `sigyn-engine` (`vault::trust`), called by both the CLI and web unlock
  paths, so the two surfaces can no longer diverge on it.
- The single-vault and hierarchical policy engines now share one
  `evaluate_member_grant` primitive for the role/env/pattern rules, instead of two
  copies that had already drifted (which is how the `key: None` and cross-level
  bugs slipped into only one engine).
- `env promote` authorizes source/target through the shared, hierarchy-aware
  `check_access_for_env`, so org-level constraints apply to promotion too.
- Dependency-advisory scan (`cargo deny`): the git2 unsound advisories
  RUSTSEC-2026-0183/0184 are ignored with justification — the fix is only in a
  semver-breaking git2 0.21 that drops the ssh/https features Sigyn requires, and
  the affected APIs (`Remote::list`, `BlameHunk`) are not used here.

### Notes

- Pre-existing env files remain readable; newly written env files no longer store a
  redundant plaintext content hash.
