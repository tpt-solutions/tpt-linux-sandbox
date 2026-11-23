#!/bin/sh
# Install tpt-sandbox from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/TPT-Solutions/tpt-linux-sandbox/master/install.sh | sh
#
# Set INSTALL_DIR to change the destination (default: $HOME/.local/bin).
set -eu

REPO="TPT-Solutions/tpt-linux-sandbox"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

if [ "$(uname -s)" != "Linux" ]; then
    echo "tpt-sandbox runs on Linux only." >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64) ARCH=x86_64 ;;
    aarch64 | arm64) ARCH=aarch64 ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

TARGET="${ARCH}-unknown-linux-musl"
URL="https://github.com/${REPO}/releases/latest/download/tpt-sandbox-${TARGET}.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "downloading tpt-sandbox for ${TARGET}..."
curl -fsSL "$URL" -o "$TMP/tpt-sandbox.tar.gz"
tar -xzf "$TMP/tpt-sandbox.tar.gz" -C "$TMP"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP/tpt-sandbox-${TARGET}/tpt-sandbox" "$INSTALL_DIR/tpt-sandbox"
echo "installed $INSTALL_DIR/tpt-sandbox"
echo "run 'tpt-sandbox --doctor' to check this machine."
