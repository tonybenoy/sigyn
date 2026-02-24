#!/bin/sh
# Sigyn uninstaller — removes binaries and optionally all data.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tonybenoy/sigyn/main/uninstall.sh | sh

set -eu

INSTALL_DIR="${SIGYN_INSTALL_DIR:-$HOME/.sigyn/bin}"
DATA_DIR="$HOME/.sigyn"

say() { printf '  \033[1;32m%s\033[0m %s\n' "$1" "$2"; }

# ---------- remove binaries --------------------------------------------------

for bin in sigyn sigyn-recovery; do
    # Check installed via install.sh
    if [ -f "${INSTALL_DIR}/${bin}" ]; then
        rm -f "${INSTALL_DIR}/${bin}"
        say "removed" "${INSTALL_DIR}/${bin}"
    fi
    # Check installed via cargo
    if [ -f "$HOME/.cargo/bin/${bin}" ]; then
        rm -f "$HOME/.cargo/bin/${bin}"
        say "removed" "$HOME/.cargo/bin/${bin}"
    fi
done

# Remove bin dir if empty
if [ -d "$INSTALL_DIR" ] && [ -z "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
    rmdir "$INSTALL_DIR"
fi

# ---------- clean PATH from shell profiles -----------------------------------

for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    if [ -f "$profile" ] && grep -qF "$INSTALL_DIR" "$profile" 2>/dev/null; then
        # Remove the Sigyn PATH lines
        sed_cmd="sed -i"
        case "$(uname -s)" in
            Darwin) sed_cmd="sed -i ''" ;;
        esac
        eval "$sed_cmd" '/# Sigyn/d' "$profile"
        eval "$sed_cmd" "\\|${INSTALL_DIR}|d" "$profile"
        say "cleaned" "$profile"
    fi
done

# ---------- optionally remove data -------------------------------------------

printf '\n  Remove all Sigyn data (%s)? This deletes identities, vaults, and config. [y/N] ' "$DATA_DIR"
read -r answer </dev/tty 2>/dev/null || answer="n"

case "$answer" in
    [yY]|[yY][eE][sS])
        rm -rf "$DATA_DIR"
        say "removed" "$DATA_DIR"
        ;;
    *)
        say "kept" "$DATA_DIR"
        ;;
esac

printf '\n  \033[1;32mSigyn uninstalled.\033[0m\n\n'
