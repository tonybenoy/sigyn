# Web GUI

Sigyn includes an optional local web GUI for managing vaults and secrets through your browser. It provides a visual alternative to the CLI while using the same engine and security model underneath.

## Building

The web GUI is behind a feature flag to keep the default binary lean:

```bash
cargo build --release --features web
```

## Usage

```bash
sigyn web                     # Start on http://127.0.0.1:9847
sigyn web --open              # Start and open browser
sigyn web --port 8080         # Custom port
sigyn web --timeout 60        # 60-minute session timeout
```

| Flag | Description |
|---|---|
| `--port <PORT>` | Port to listen on (default: 9847) |
| `--timeout <MINUTES>` | Session timeout in minutes (default: 30) |
| `--open` | Open browser automatically |

## Features

- **Identity login** -- Select your identity and enter your passphrase to authenticate
- **Vault dashboard** -- Browse all vaults in a card-based layout
- **Secret management** -- View, add, edit, and delete secrets with full policy enforcement
- **Environment switching** -- Switch between dev/staging/prod via dropdown
- **Member list** -- View vault members and their roles
- **Audit log** -- Browse the hash-chained audit trail with timestamps and actors
- **Vault info** -- View vault metadata (ID, owner, environments, description)

## Architecture

The web GUI is implemented as a Rust crate (`sigyn-web`) with:

- **Backend**: [axum](https://github.com/tokio-rs/axum) HTTP server calling `sigyn-engine` directly
- **Frontend**: Single embedded HTML file using Alpine.js and Tailwind CSS (no build tooling)
- **Sessions**: In-memory session store with TTL expiry (mirrors the [agent](cli-reference.md#agent) daemon pattern)

The entire GUI is compiled into the binary via `include_str!` -- no external files needed at runtime.

## Security

### Localhost-only binding

The server binds exclusively to `127.0.0.1`. It is **never** accessible from other machines on the network.

### Session management

- 256-bit cryptographically random session tokens
- `HttpOnly; SameSite=Strict` cookies (no JavaScript access, no cross-site leakage)
- Configurable timeout with automatic session sweep (default: 30 minutes of inactivity)
- Key material is held in memory only while the session is active

### Passphrase handling

- The passphrase is used once to call `IdentityStore::load()`, then immediately cleared
- It is never stored in the session, never logged, never written to disk
- Only the derived `LoadedIdentity` (private keys) is cached, matching the agent daemon's approach

### Rate limiting

Failed login attempts are rate-limited to 5 per minute per fingerprint to prevent brute-force passphrase guessing.

### Policy enforcement

All secret operations go through the same `PolicyEngine::evaluate()` checks as the CLI. Every mutation generates a signed audit log entry.

## REST API

The web GUI exposes a JSON REST API that the frontend consumes. These endpoints are also usable for scripting if needed:

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | No | `{fingerprint, passphrase}` -- create session |
| `POST` | `/api/auth/logout` | Yes | Destroy session |
| `GET` | `/api/auth/status` | Yes | Check session, return identity info |
| `GET` | `/api/identities` | No | List identities (public info only) |
| `GET` | `/api/vaults` | Yes | List vault names |
| `GET` | `/api/vaults/:name` | Yes | Vault info (triggers unlock) |
| `GET` | `/api/vaults/:vault/envs/:env/secrets` | Yes | List secrets (values masked) |
| `GET` | `/api/vaults/:vault/envs/:env/secrets/:key` | Yes | Read secret value |
| `POST` | `/api/vaults/:vault/envs/:env/secrets` | Yes | Set secret `{key, value, secret_type}` |
| `DELETE` | `/api/vaults/:vault/envs/:env/secrets/:key` | Yes | Delete secret |
| `GET` | `/api/vaults/:vault/audit?limit=50` | Yes | Audit log entries |

## Comparison with TUI

| Feature | TUI (`sigyn tui`) | Web GUI (`sigyn web`) |
|---|---|---|
| Read secrets | View keys (values masked) | View keys + reveal values |
| Write secrets | Not supported | Full CRUD |
| Members | Read-only list | Read-only list |
| Audit log | Last 20 entries | Paginated (up to 100) |
| Environments | Fixed at launch | Switchable via dropdown |
| Build requirement | Default build | `--features web` |
| External deps | None | Browser |
