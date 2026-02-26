# Contributing to Sigyn

First off, thank you for considering contributing to Sigyn! It's people like you who make Sigyn such a great tool.

## Code of Conduct

Please be respectful and professional in all interactions.

## How Can I Contribute?

### Reporting Bugs

- Use the GitHub issue tracker.
- Check if the bug has already been reported.
- Include a clear description, steps to reproduce, and your environment (OS, Rust version).

### Suggesting Enhancements

- Open a GitHub issue to discuss the enhancement.
- Provide a clear use case for why this feature is needed.

### Pull Requests

- Fork the repository.
- Create a new branch for your feature or bugfix.
- Ensure your code follows the existing style.
- **Write tests** for your changes.
- Ensure all tests pass: `cargo test --all --features sigyn-cli/fast-kdf`
- Ensure the code is linted: `cargo clippy -- -D warnings`
- Ensure the code is formatted: `cargo fmt --all -- --check`
- Submit a pull request.

## Development Setup

### Prerequisites

- Rust 1.75 or later.
- Git.

### Building from Source

```bash
git clone https://github.com/tonybenoy/sigyn.git
cd sigyn
cargo build
```

### Running Tests

Run all tests (the `fast-kdf` feature uses lightweight Argon2 params to speed up tests):

```bash
cargo test --all --features sigyn-cli/fast-kdf
```

Run integration tests:

```bash
cargo test -p sigyn-integration-tests
```

### Linting and Formatting

We use `clippy` and `rustfmt` to maintain code quality.

```bash
cargo clippy -- -D warnings
cargo fmt --all
```

## Project Structure

- `crates/sigyn-core`: Pure library (publishable) -- cryptography, policy, CRDT, types. Zero I/O dependencies.
- `crates/sigyn-engine`: I/O layer -- filesystem, git sync, audit persistence. Depends on and re-exports `sigyn-core`.
- `crates/sigyn-cli`: The main CLI application.
- `crates/sigyn-recovery`: A standalone recovery tool.
- `tests/integration`: Integration tests that exercise the full CLI.

## Adding a New Command

1.  Add the command definition in `crates/sigyn-cli/src/commands/mod.rs` (if it's a new group) or in the relevant subcommand file (e.g., `crates/sigyn-cli/src/commands/secret.rs`).
2.  Implement the logic in the command file.
3.  Add an integration test in `tests/integration/` to verify the new command works as expected.

## Documentation

The documentation lives in `docs-site/src/` and is served via mdBook.

To build the docs site locally:

```bash
cd docs-site
mdbook serve
```

---

Thank you for contributing!
