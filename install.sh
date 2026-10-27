#!/usr/bin/env bash
#
# Fikrado Security — installer for Linux and macOS
#
#   curl -fsSL https://raw.githubusercontent.com/fikrado2/fikrado-security-cli/main/install.sh | bash
#
# Downloads the latest standalone binary for this machine and installs it
# to ~/.local/bin/fikrado (override with FIKRADO_PREFIX).
#
set -euo pipefail

REPO="fikrado2/fikrado-security-cli"
PREFIX="${FIKRADO_PREFIX:-$HOME/.local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  linux)  os_name="linux" ;;
  darwin) os_name="macos" ;;
  *) echo "Unsupported OS: $os (download a binary manually from https://github.com/$REPO/releases)" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) arch_name="x64" ;;
  aarch64|arm64) arch_name="arm64" ;;
  *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac

asset="fikrado-${os_name}-${arch_name}"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "→ downloading ${asset}…"
if ! curl -fsSL "$url" -o "$tmp"; then
  echo "✗ download failed — check https://github.com/$REPO/releases" >&2
  exit 1
fi

chmod +x "$tmp"
mkdir -p "$PREFIX"
mv "$tmp" "$PREFIX/fikrado"
trap - EXIT

echo "✔ installed to $PREFIX/fikrado"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "  add it to PATH:  export PATH=\"$PREFIX:\$PATH\"" ;;
esac
"$PREFIX/fikrado" --version >/dev/null 2>&1 && echo "  run: fikrado"
