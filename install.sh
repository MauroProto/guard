#!/bin/sh
# Guard installer — downloads and installs the guard binary.
# Usage: curl -fsSL https://raw.githubusercontent.com/nori-mau/guard/main/install.sh | sh

set -e

REPO="nori-mau/guard"
BINARY="guard"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[31m'
GREEN='\033[32m'
CYAN='\033[36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info() { printf "  ${CYAN}ℹ${RESET} %s\n" "$1"; }
ok()   { printf "  ${GREEN}✔${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✖${RESET} %s\n" "$1"; exit 1; }

printf "\n  🛡  ${BOLD}Guard Installer${RESET}\n\n"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       fail "Unsupported architecture: $ARCH" ;;
esac

case "$OS" in
    linux|darwin) ;;
    *) fail "Unsupported OS: $OS" ;;
esac

info "Detected: ${OS}/${ARCH}"

# Check if Go is available (preferred method)
if command -v go > /dev/null 2>&1; then
    info "Go found — installing via go install..."
    go install "github.com/${REPO}/cmd/guard@latest" 2>&1

    # Check if GOPATH/bin is in PATH
    GOBIN=$(go env GOPATH)/bin
    if command -v guard > /dev/null 2>&1; then
        ok "Installed: $(which guard)"
    elif [ -f "${GOBIN}/guard" ]; then
        ok "Installed: ${GOBIN}/guard"
        printf "\n  ${DIM}Add this to your shell profile:${RESET}\n"
        printf "  ${CYAN}export PATH=\"\$PATH:${GOBIN}\"${RESET}\n"
    fi

    printf "\n  ${GREEN}${BOLD}Done!${RESET} Run ${CYAN}guard${RESET} to get started.\n\n"
    exit 0
fi

# Fallback: download pre-built binary from GitHub releases
info "Go not found — downloading pre-built binary..."

RELEASE_URL="https://github.com/${REPO}/releases/latest/download/guard-${OS}-${ARCH}"
TMP=$(mktemp)

if command -v curl > /dev/null 2>&1; then
    curl -fsSL "$RELEASE_URL" -o "$TMP" 2>/dev/null
elif command -v wget > /dev/null 2>&1; then
    wget -q "$RELEASE_URL" -O "$TMP" 2>/dev/null
else
    fail "Neither curl nor wget found."
fi

if [ ! -s "$TMP" ]; then
    # No pre-built binary yet — guide to install Go
    rm -f "$TMP"
    printf "\n  ${DIM}Pre-built binaries not available yet.${RESET}\n"
    printf "  ${DIM}Install Go first, then run:${RESET}\n\n"
    printf "  ${CYAN}go install github.com/${REPO}/cmd/guard@latest${RESET}\n\n"

    case "$OS" in
        darwin) printf "  ${DIM}Install Go:${RESET} ${CYAN}brew install go${RESET}\n" ;;
        linux)  printf "  ${DIM}Install Go:${RESET} ${CYAN}https://go.dev/dl/${RESET}\n" ;;
    esac
    printf "\n"
    exit 1
fi

chmod +x "$TMP"

# Try /usr/local/bin, fall back to ~/bin
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "${INSTALL_DIR}/${BINARY}"
    ok "Installed: ${INSTALL_DIR}/${BINARY}"
else
    info "Need sudo to install to ${INSTALL_DIR}"
    sudo mv "$TMP" "${INSTALL_DIR}/${BINARY}"
    ok "Installed: ${INSTALL_DIR}/${BINARY}"
fi

printf "\n  ${GREEN}${BOLD}Done!${RESET} Run ${CYAN}guard${RESET} to get started.\n\n"
