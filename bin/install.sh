#!/bin/sh
set -e

REPO="circlesac/aws-sts-login"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS-$ARCH" in
	darwin-arm64)  NAME="aws-sts-login-darwin-arm64" ;;
	darwin-x86_64) NAME="aws-sts-login-darwin-x64" ;;
	linux-aarch64) NAME="aws-sts-login-linux-arm64" ;;
	linux-x86_64)  NAME="aws-sts-login-linux-x64" ;;
	*) echo "Unsupported platform: $OS-$ARCH"; exit 1 ;;
esac

VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
URL="https://github.com/$REPO/releases/download/$VERSION/${NAME}.tar.gz"

echo "Installing aws-sts-login $VERSION..."
curl -fsSL "$URL" | tar xz -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/aws-sts-login"
echo "Installed to $INSTALL_DIR/aws-sts-login"
