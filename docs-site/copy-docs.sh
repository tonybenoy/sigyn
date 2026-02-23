#!/bin/bash
# Copy docs/ files into mdBook src/ directory for building the site.
# Run before `mdbook build docs-site`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
DOCS_DIR="$(dirname "$SCRIPT_DIR")/docs"

# Copy docs that map directly to mdBook pages
for file in architecture.md security.md cli-reference.md getting-started.md delegation.md sync.md multi-vault.md; do
    if [ -f "$DOCS_DIR/$file" ]; then
        cp "$DOCS_DIR/$file" "$SRC_DIR/$file"
    fi
done

echo "Docs copied to $SRC_DIR"
