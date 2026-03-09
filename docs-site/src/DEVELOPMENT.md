# Development Guide

This guide is for developers who want to hack on Sigyn's codebase.

## Technical Principles

1.  **I/O Separation**: `sigyn-core` MUST NOT perform any I/O (filesystem, network). All I/O lives in `sigyn-engine`. This makes the core library publishable, testable, and portable.
2.  **Safety First**: Always use `secrecy::Secret<T>` for sensitive data. Ensure zeroization on drop.
3.  **Atomic Operations**: Filesystem operations in the CLI should be atomic. Use `tempfile` and `persist()`.
4.  **Typed Errors**: Use `thiserror` in the core library for precise error handling. Use `anyhow` in the CLI for context-rich error reporting.
5.  **Synchronous Core**: The core library is synchronous to keep it simple and avoid async overhead where not needed. The CLI handles async tasks (like networking) using `tokio`.

## Codebase Walkthrough

### `sigyn-core` (Pure Library)

Zero I/O dependencies. Publishable to crates.io. Contains:

- **`crypto/`**: Low-level cryptographic primitives. We use `x25519-dalek` for key exchange and `chacha20poly1305` for symmetric encryption.
- **`policy/`**: The RBAC and ACL engine. This is the "brain" that decides if an operation is allowed.
- **`sync/`**: CRDT-based synchronization logic. It uses vector clocks to detect conflicts.
- **`vault/`**: Vault manifest types and env file encryption/decryption (pure computation only).
- **`secrets/`**, **`identity/`**, **`delegation/`**, **`forks/`**, **`rotation/`**, **`audit/`**, **`hierarchy/`**, **`environment/`**: Types, algorithms, and pure logic.

### `sigyn-engine` (I/O Layer)

Depends on and re-exports `sigyn-core`. Contains all filesystem and git operations:

- **`vault/`**: Env file read/write, vault locking (`fd-lock`), vault path resolution.
- **`sync/`**: Git-based sync engine (`git2`).
- **`audit/`**: File-based audit log, git anchoring, witness log persistence.
- **`identity/`**: Identity store, MFA store, session store (all filesystem).
- **`hierarchy/`**: Hierarchy paths, slot management, git remote resolution.
- **`forks/`**: Fork creation with filesystem operations.

### `sigyn-cli`

The CLI uses `clap` for argument parsing.

- **`commands/`**: Each file here corresponds to a major subcommand (e.g., `secret`, `vault`, `identity`).
- **`inject/`**: Logic for injecting secrets into processes via environment variables or Unix sockets.
- **`tui/`**: The interactive TUI built with `ratatui`.

## How-To Guides

### Adding a New Secret Type

1.  Update the `SecretValue` enum in `crates/sigyn-core/src/secrets/types.rs`.
2.  Implement validation logic in `crates/sigyn-core/src/secrets/validation.rs`.
3.  Update the CLI to support the new type in `crates/sigyn-cli/src/commands/secret.rs`.

### Adding a New Import Source

1.  Add a new module in `crates/sigyn-cli/src/importexport/`.
2.  Implement the `Importer` trait (or follow the pattern of existing importers like `doppler.rs`).
3.  Register the new source in `crates/sigyn-cli/src/commands/import.rs`.

### Working on the TUI

The TUI uses `ratatui` with `crossterm` as the backend.

- The entry point is `crates/sigyn-cli/src/tui/mod.rs`.
- We use a component-based approach for different screens (Vault list, Secret list, etc.).

To test the TUI during development, you can run:

```bash
cargo run -- tui
```

## Testing Strategy

Sigyn uses 5 test layers: unit tests, integration tests, CLI workflow tests, E2E tests, and adversarial security tests.

```bash
# Run all tests (fast KDF for speed)
cargo test --all --features sigyn-cli/fast-kdf

# E2E test (requires release build)
cargo build --release && bash tests/e2e_test.sh

# Adversarial security test
bash tests/adversarial_test.sh
```

See the [Testing](./testing.md) page for the full testing guide, including how to write tests and CI integration.

## Debugging

You can use the `RUST_LOG` environment variable to see detailed logs (if implemented):

```bash
RUST_LOG=debug sigyn vault list
```

## Benchmarking

We use `criterion` for benchmarking performance-critical parts like the CRDT merge and encryption.

```bash
cargo bench
```
