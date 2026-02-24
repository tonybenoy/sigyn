#!/bin/sh
# Sigyn installer — works on macOS, Linux, and WSL.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/install.sh | sh
#
# Options (env vars):
#   SIGYN_INSTALL_DIR  — where to put the binaries (default: ~/.sigyn/bin)
#   SIGYN_VERSION      — version to install (default: latest)

set -eu

REPO="tonybenoy/sigyn"
INSTALL_DIR="${SIGYN_INSTALL_DIR:-$HOME/.sigyn/bin}"
VERSION="${SIGYN_VERSION:-latest}"

# ---------- helpers ----------------------------------------------------------

say()  { printf '  \033[1;32m%s\033[0m %s\n' "$1" "$2"; }
err()  { printf '  \033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

# ---------- detect platform --------------------------------------------------

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)   os_part="unknown-linux-gnu" ;;
        Darwin)  os_part="apple-darwin" ;;
        MINGW*|MSYS*|CYGWIN*) err "use install.ps1 for Windows (irm …/install.ps1 | iex)" ;;
        *)       err "unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch_part="x86_64" ;;
        aarch64|arm64) arch_part="aarch64" ;;
        *)             err "unsupported architecture: $arch" ;;
    esac

    echo "${arch_part}-${os_part}"
}

# ---------- resolve version --------------------------------------------------

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        need curl
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
        [ -n "$VERSION" ] || err "could not determine latest release"
    fi
}

# ---------- download & install -----------------------------------------------

download_and_install() {
    target="$1"
    need curl
    need tar

    resolve_version
    tag="${VERSION#v}"  # strip leading v if present for archive name
    archive="sigyn-${VERSION}-${target}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${VERSION}/${archive}"

    say "info" "installing sigyn ${VERSION} for ${target}"
    say "info" "destination: ${INSTALL_DIR}"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    say "fetch" "$url"
    http_code="$(curl -fsSL -o "${tmpdir}/${archive}" -w '%{http_code}' "$url" 2>/dev/null)" || true

    if [ "$http_code" != "200" ] || [ ! -s "${tmpdir}/${archive}" ]; then
        say "warn" "pre-built binary not found — falling back to cargo install"
        install_from_source
        return
    fi

    # Verify checksum if available
    checksum_url="https://github.com/${REPO}/releases/download/${VERSION}/checksums.sha256"
    if curl -fsSL -o "${tmpdir}/checksums.sha256" "$checksum_url" 2>/dev/null; then
        say "verify" "checking SHA-256 checksum"
        cd "$tmpdir"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c checksums.sha256 --ignore-missing 2>/dev/null || err "checksum verification failed"
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -c checksums.sha256 --ignore-missing 2>/dev/null || err "checksum verification failed"
        else
            say "warn" "no sha256sum or shasum found, skipping checksum verification"
        fi
        cd - >/dev/null
        say "ok" "checksum verified"
    else
        say "warn" "checksums not available for this release, skipping verification"
    fi

    tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"

    mkdir -p "$INSTALL_DIR"

    for bin in sigyn sigyn-recovery; do
        if [ -f "${tmpdir}/${bin}" ]; then
            cp "${tmpdir}/${bin}" "${INSTALL_DIR}/${bin}"
            chmod +x "${INSTALL_DIR}/${bin}"
            say "ok" "installed ${bin}"
        fi
    done

    add_to_path
}

install_from_source() {
    need cargo
    say "build" "compiling from source (this may take a few minutes)..."
    cargo install --git "https://github.com/${REPO}.git" --bin sigyn  sigyn-cli
    cargo install --git "https://github.com/${REPO}.git" --bin sigyn-recovery sigyn-recovery
    say "ok" "installed via cargo"
    printf '\n  Binaries are in %s\n' "$(dirname "$(command -v sigyn 2>/dev/null || echo "$HOME/.cargo/bin/sigyn")")"
}

# ---------- PATH setup -------------------------------------------------------

add_to_path() {
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;  # already on PATH
        *)
            say "path" "add ${INSTALL_DIR} to your PATH"

            profile=""
            if [ -f "$HOME/.zshrc" ]; then
                profile="$HOME/.zshrc"
            elif [ -f "$HOME/.bashrc" ]; then
                profile="$HOME/.bashrc"
            elif [ -f "$HOME/.profile" ]; then
                profile="$HOME/.profile"
            fi

            line="export PATH=\"${INSTALL_DIR}:\$PATH\""

            if [ -n "$profile" ]; then
                if ! grep -qF "$INSTALL_DIR" "$profile" 2>/dev/null; then
                    printf '\n# Sigyn\n%s\n' "$line" >> "$profile"
                    say "ok" "added to ${profile}"
                fi
            fi

            printf '\n  To use now, run:\n    export PATH="%s:$PATH"\n' "$INSTALL_DIR"
            ;;
    esac

    printf '\n  \033[1;32mSigny installed!\033[0m Run \033[1msigyn --version\033[0m to verify.\n\n'
}

# ---------- main -------------------------------------------------------------

target="$(detect_target)"
download_and_install "$target"
