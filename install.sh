#!/bin/sh
# Install tpt-sandbox from a GitHub release, verifying its SHA-256 checksum.
#
#   curl -fsSL https://raw.githubusercontent.com/TPT-Solutions/tpt-linux-sandbox/master/install.sh | sh
#
# Environment:
#   TPT_SANDBOX_VERSION  release tag to install, e.g. v0.1.0 (default: latest)
#   INSTALL_DIR          destination directory (default: $HOME/.local/bin)
#
# The download is refused if its checksum file is missing or does not match.
set -eu

REPO="TPT-Solutions/tpt-linux-sandbox"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${TPT_SANDBOX_VERSION:-latest}"

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
ARCHIVE="tpt-sandbox-${TARGET}.tar.gz"
if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/${REPO}/releases/latest/download"
else
    BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "downloading tpt-sandbox ${VERSION} for ${TARGET}..."
curl -fsSL "${BASE}/${ARCHIVE}" -o "$TMP/$ARCHIVE"
curl -fsSL "${BASE}/${ARCHIVE}.sha256" -o "$TMP/checksum"

# The checksum file is "<hash>  <name>"; only the hash is compared.
expected="$(awk '{print $1; exit}' "$TMP/checksum")"
actual="$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "checksum mismatch for ${ARCHIVE}; refusing to install" >&2
    exit 1
fi
echo "checksum verified"

tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP/tpt-sandbox-${TARGET}/tpt-sandbox" "$INSTALL_DIR/tpt-sandbox"
echo "installed $INSTALL_DIR/tpt-sandbox"
echo "run 'tpt-sandbox --doctor' to check this machine."
