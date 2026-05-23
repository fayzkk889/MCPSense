#!/bin/sh
# MCPSense Installer
# Usage: curl -sSL https://mcpsense.site/install.sh | sh
#
# Detects your OS and architecture, downloads the correct binary
# from GitHub Releases, and installs it to /usr/local/bin.

set -e

REPO="fayzkk889/MCPSense"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="mcpsense"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[0;90m'
RESET='\033[0m'

info()  { printf "${CYAN}[mcpsense]${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}[mcpsense]${RESET} %s\n" "$1"; }
fail()  { printf "${RED}[mcpsense]${RESET} %s\n" "$1"; exit 1; }

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*)   OS="linux" ;;
  Darwin*)  OS="darwin" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *) fail "Unsupported operating system: $OS" ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   ARCH="amd64" ;;
  arm64|aarch64)   ARCH="arm64" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

# Windows arm64 is not supported
if [ "$OS" = "windows" ] && [ "$ARCH" = "arm64" ]; then
  fail "Windows ARM64 is not supported. Use Windows x86_64 (amd64)."
fi

info "Detected: ${OS}/${ARCH}"

# Determine latest version
info "Fetching latest release..."
if command -v curl > /dev/null 2>&1; then
  LATEST=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
elif command -v wget > /dev/null 2>&1; then
  LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
else
  fail "Neither curl nor wget found. Install one and try again."
fi

if [ -z "$LATEST" ]; then
  fail "Could not determine latest version. Check https://github.com/${REPO}/releases"
fi

info "Latest version: v${LATEST}"

# Build download URL
if [ "$OS" = "windows" ]; then
  FILENAME="MCPSense_${LATEST}_${OS}_${ARCH}.zip"
else
  FILENAME="MCPSense_${LATEST}_${OS}_${ARCH}.tar.gz"
fi

URL="https://github.com/${REPO}/releases/download/v${LATEST}/${FILENAME}"

# Download
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${FILENAME}..."
if command -v curl > /dev/null 2>&1; then
  curl -sSL "$URL" -o "${TMPDIR}/${FILENAME}"
elif command -v wget > /dev/null 2>&1; then
  wget -q "$URL" -O "${TMPDIR}/${FILENAME}"
fi

if [ ! -f "${TMPDIR}/${FILENAME}" ]; then
  fail "Download failed. URL: ${URL}"
fi

# Extract
info "Extracting..."
cd "$TMPDIR"
if [ "$OS" = "windows" ]; then
  unzip -q "$FILENAME"
else
  tar -xzf "$FILENAME"
fi

if [ ! -f "${BINARY_NAME}" ]; then
  fail "Binary not found after extraction. Archive may have a different structure."
fi

chmod +x "$BINARY_NAME"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
else
  info "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
fi

# Verify
if command -v mcpsense > /dev/null 2>&1; then
  VERSION=$(mcpsense version 2>&1)
  ok "Installed successfully: ${VERSION}"
  echo ""
  printf "${DIM}  Quick start:${RESET}\n"
  printf "${DIM}    mcpsense scan ./my-mcp-server${RESET}\n"
  printf "${DIM}    mcpsense scan ./mcp.json${RESET}\n"
  printf "${DIM}    mcpsense --help${RESET}\n"
  echo ""
  ok "Docs: https://github.com/${REPO}"
else
  ok "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"
  echo "  You may need to add ${INSTALL_DIR} to your PATH."
fi
