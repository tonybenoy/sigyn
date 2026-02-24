# Feature Audit

Audit of all planned, documented, and implemented features as of 2026-02-24.

## Legend

- **Functional** — implemented and wired into the CLI
- **Dead code** — implementation exists but is never called from any real code path
- **Stub** — CLI command exists but does nothing meaningful
- **Ghost** — documented but no implementation exists
- **Partial** — partly functional with caveats

---

## Fully Functional Features

These work end-to-end from the CLI.

| Feature | CLI command | Notes |
|---------|-------------|-------|
| Identity management | `sigyn identity create/list/show` | Keypair generation, Argon2id passphrase wrapping |
| Vault management | `sigyn vault create/list/info` | Envelope encryption, multi-member headers |
| Secret CRUD | `sigyn secret set/get/list/remove/generate` | ChaCha20-Poly1305 encryption, typed values |
| Environment management | `sigyn env create/list/promote` | Per-env encrypted files, promotion across envs |
| RBAC policy | `sigyn policy show/member-add/member-remove/check` | 7-level role hierarchy, per-key ACLs |
| Delegation | `sigyn delegation invite/accept/revoke/tree/pending` | Ed25519-signed invitations, cascade revocation |
| Audit trail | `sigyn audit tail/query/verify/export/witness` | Hash-chained, Ed25519-signed entries |
| TOTP-based MFA | `sigyn mfa setup/disable/status/backup` | HKDF-derived encryption, session grace period, QR codes |
| Process injection | `sigyn run -- cmd` | Env var injection without writing to disk |
| Secret export | `sigyn run export --format dotenv/json/k8s/docker/shell` | Multiple output formats |
| Unix socket server | `sigyn run serve` | `GET`/`LIST`/`QUIT` protocol, chmod 600 |
| Import | `sigyn import dotenv/json/doppler/aws/gcp/1password` | Multiple cloud provider formats |
| TUI dashboard | `sigyn tui` | ratatui, 4 tabs, real vault data loading |
| Rotation key | `sigyn rotate key` | Rotates a secret value |
| Rotation breach mode | `sigyn rotate breach-mode` | Emergency re-key |
| Rotation due check | `sigyn rotate due` | Checks secrets against schedule |
| Rotation dead check | `sigyn rotate dead-check` | Finds stale secrets |
| Git sync push/pull | `sigyn sync push/pull/status` | Real git2 operations |
| Recovery split | `sigyn-recovery split` | Shamir K-of-N shard generation |
| Recovery snapshots | `sigyn-recovery snapshots` | Lists git commit history |
| Shell completions | `sigyn completions bash/zsh/fish/powershell` | clap_complete |
| Doctor | `sigyn doctor` | Health checks |
| Status | `sigyn status` | Current vault/env info |
| Init | `sigyn init` | Default config setup |
| Project config | `sigyn project init` | `.sigyn.toml` per-project defaults |

---

## Dead Code (implemented, never called)

### IP Allowlist Enforcement

**What exists:** `Constraints.ip_allowlist` field, `check_ip()` method with CIDR support, `AccessRequest.ip` field, engine calls `check_ip` when `ip.is_some()`.

**Why dead:** Every `AccessRequest` in the CLI passes `ip: None`. There is no server to obtain a client IP from. The constraint logic works (tested) but is never exercised at runtime.

**Can we add it?** Yes, but only meaningful if we add a network-facing component. Options:
- Wire it into `sigyn run serve` (socket server) by reading the peer socket address
- Wire it into a future HTTP API / remote vault server
- Remove it if we commit to being purely local CLI

### AllowWithWarning Policy Decision

**What exists:** `PolicyDecision::AllowWithWarning(String)` variant, handled in `check_access()` and `policy check` match arms.

**Why dead:** `PolicyEngine::evaluate()` never returns this variant. No code path constructs it.

**Can we add it?** Yes. Useful for soft warnings like:
- Expiry approaching (e.g., member expires in < 24 hours)
- High backup code consumption (e.g., only 1 backup code remaining)
- MFA session about to expire

### Notifications Module

**What exists:** Full webhook implementation in `crates/sigyn-cli/src/notifications/`. Supports HTTP POST with optional HMAC signing, config load/save from `notifications.toml`, `NotificationEvent` enum.

**Why dead:** `#[allow(dead_code)]` on the module. Zero callers from any CLI command.

**Can we add it?** Yes. Wire `notify_event()` calls into:
- `secret set/remove` — secret change notifications
- `rotate key` — rotation notifications
- `delegation revoke` — member revocation alerts
- `audit verify` — chain integrity failure alerts
- `rotate due` — upcoming rotation reminders

### Rotation Hooks

**What exists:** `rotation/hooks.rs` with `execute_rotation_hooks()` — runs shell commands with `SIGYN_ROTATED_KEY` and `SIGYN_ENV` env vars. `RotationSchedule.hooks` field.

**Why dead:** `sigyn rotate key` performs rotation but never calls hook execution.

**Can we add it?** Yes, straightforward. After `rotate key` completes, load the schedule for that key, run its hooks. Enables post-rotation actions like restarting services, updating cloud credentials, etc.

### Fork Approval

**What exists:** `forks/approval.rs` with `ForkApproval`, `ForkApprovalStatus`, `approve()`, `reject()`, `is_approved()`. Well-tested.

**Why dead:** No CLI command references `ForkApproval`. Fork commands are all stubs (see below).

**Can we add it?** Yes, but requires fork commands to be functional first (see Stub section).

### GitAnchor (Audit Anchoring)

**What exists:** `audit/anchor.rs` — `GitAnchor` struct with `create_anchor()` and `verify_anchor()`. Anchors an audit chain checkpoint to a git commit hash for external verifiability.

**Why dead:** `sigyn audit anchor` is documented in cli-reference but never wired. The `AuditCommands` enum doesn't have an `Anchor` variant.

**Can we add it?** Yes. Add `Anchor` subcommand to `AuditCommands` that calls `create_anchor()` on the current audit log state. Useful for compliance: "as of git commit X, the audit chain was verified intact."

### Misc Dead Utilities

| Item | Location | Notes |
|------|----------|-------|
| `import_file()` | `importexport/mod.rs` | Auto-detect import format. Could wire into `sigyn import auto <file>` |
| `collect_env_vars()` | `inject/process.rs` | Utility to collect env vars into HashMap. Could be used in process injection |
| `print_error()` | `output/mod.rs` | Styled error printer. Could replace raw `eprintln!` calls |
| `--dry-run` flag | `main.rs` Cli struct | Parsed by clap, never read. Could add dry-run support to write operations |
| `auto_sync` config | `CliConfig` | Stored but never triggers automatic sync |

---

## Stub Commands (exist in CLI, do nothing)

### Fork Commands

**`sigyn fork create/list/status/sync`** — all four are hollow.

- `fork create` validates the mode string then discards it. Never calls `create_leashed_fork()` / `create_unleashed_fork()` which are fully implemented in `forks/leash.rs`.
- `fork list` checks if `forks.cbor` exists (it never would) and returns.
- `fork status` prints hardcoded `"status": "active"`.
- `fork sync` prints a success message with no vault operations.

**Can we add it?** Yes. The core logic in `forks/leash.rs` is complete. The CLI just needs to call it:
- `fork create` → call `create_leashed_fork()` or `create_unleashed_fork()`
- `fork list` → read fork manifests from the forks directory
- `fork status` → read fork metadata and expiry
- `fork sync` → merge fork changes back into the parent vault

### Sync Resolve

**`sigyn sync resolve <key> --strategy <s>`** — constructs a `ConflictResolution` enum, prints success, resolves nothing.

**Can we add it?** Yes, but needs a conflict storage mechanism. Currently there's no way to detect or persist conflicts from `git pull`. Would need: conflict detection during pull, conflict file storage, then `resolve` reads and applies the chosen strategy.

### Sync Configure

**`sigyn sync configure --remote-url <url>`** — prints the URL but never calls `engine.add_remote()`.

**Can we add it?** Yes, trivial. Call `GitSyncEngine::add_remote()` with the provided URL.

### Rotate Schedule

**`sigyn rotate schedule`** — prints "No rotation schedules configured." No `schedule set` subcommand exists.

**Can we add it?** Yes. The `RotationSchedule` struct exists with cron expression and hooks. Need:
- `rotate schedule set --key <key> --cron <expr>` — save schedule to a config file
- `rotate schedule list` — show all configured schedules
- `rotate schedule remove --key <key>` — remove a schedule

---

## Ghost Features (documented, not implemented)

### `sigyn sync peers`

**Documented in:** `docs/cli-reference.md`, `docs/sync.md`

**Reality:** `SyncCommands` enum has no `Peers` variant. The `sync/mdns.rs` module contains `advertise_peer()` and `discover_peers()` but they use shared-filesystem `.peer.json` files, not actual mDNS. Neither function is called from any CLI command.

**Can we add it?** Yes. Options:
- Wire the existing file-based discovery into a `sigyn sync peers` command (rename module from `mdns` to `discovery`)
- Implement actual mDNS using a crate like `mdns-sd` for real LAN discovery
- Both: file-based for shared filesystems, mDNS for LAN

### Succession Dead-Man Trigger

**Documented in:** cli-reference.md (`sigyn-recovery succession`)

**Reality:** `sigyn-recovery succession show/set` reads/writes a JSON file with a successor fingerprint and `dead_man_days`. No timer, no enforcement, no automated key transfer.

**Can we add it?** Partially. A true dead-man switch requires either:
- A background daemon/cron job that checks last activity
- A server-side component (contradicts serverless design)
- A manual "break glass" flow where shards are distributed to the successor

Most realistic: make it a manual succession guide — "if the owner hasn't rotated in N days, shard holders should convene to restore."

### Recovery Restore → Usable Identity

**`sigyn-recovery restore`** writes raw 32-byte key bytes to a `.bin` file. It does not reconstruct a wrapped identity that can be used with `sigyn identity`.

**Can we add it?** Yes. After reconstructing the raw key bytes, re-wrap them with a new passphrase using `WrappedIdentity::wrap()` and save as a proper `.identity` file.

---

## Recommended Priorities

### Quick wins (< 1 day each)

1. **Wire rotation hooks** into `rotate key` — few lines of code
2. **Wire `sync configure --remote-url`** to actually call `add_remote()`
3. **Wire fork create** to call `create_leashed_fork()` / `create_unleashed_fork()`
4. **Add `AllowWithWarning`** for expiry-approaching warnings in `evaluate()`
5. **Wire `GitAnchor`** into an `audit anchor` subcommand
6. **Fix recovery restore** to output a proper wrapped identity
7. **Remove `--dry-run`** flag or implement it for `secret set/remove`
8. **Rename `mdns.rs`** to `discovery.rs` (it's not mDNS)

### Medium effort (1-3 days each)

9. **Wire notifications** into secret/rotation/revocation operations
10. **Implement `rotate schedule set/list/remove`** with persisted schedules
11. **Wire `sync peers`** command using the existing file-based discovery
12. **Implement fork list/status/sync** using fork manifests

### Larger effort (3+ days)

13. **Implement sync conflict detection and resolution** — needs conflict storage during pull
14. **Real mDNS peer discovery** — replace file-based approach with `mdns-sd` crate
15. **IP allowlist enforcement** — only meaningful with a network-facing component
16. **Succession automation** — design constraints from serverless architecture

---

## Cleanup Candidates

These can be removed if we decide not to implement them:

| Item | Action |
|------|--------|
| IP allowlist (`Constraints.ip_allowlist`, `check_ip()`, `AccessRequest.ip`) | Remove field + method, or keep for future server mode |
| `AllowWithWarning` variant | Wire it or remove it |
| `--dry-run` flag | Implement or remove from clap |
| `auto_sync` config field | Wire into post-operation sync or remove |
| "mDNS" naming | Rename to `discovery` regardless of whether we add real mDNS |
| `sigyn sync peers` docs | Remove from docs or implement the command |
| Rate limit references in docs | Already removed in recent cleanup |
