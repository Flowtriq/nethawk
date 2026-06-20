#!/bin/sh
set -e

REPO="Flowtriq/nethawk"
INSTALL_DIR="/usr/local/bin"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

LATEST=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    echo "Failed to fetch latest release"
    exit 1
fi

BINARY="nethawk-${OS}-${ARCH}"
URL="https://github.com/$REPO/releases/download/$LATEST/$BINARY"

echo "Downloading nethawk $LATEST for $OS/$ARCH..."
curl -sSfL "$URL" -o "$INSTALL_DIR/nethawk"
chmod +x "$INSTALL_DIR/nethawk"

echo "Installed nethawk $LATEST to $INSTALL_DIR/nethawk"
echo "Run: sudo nethawk"
