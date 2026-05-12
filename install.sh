#!/usr/bin/env bash
# Phantom Vault — one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/r-db/phantom-vault/main/install.sh | bash
#
# Or pin to a version:
#   curl -fsSL https://raw.githubusercontent.com/r-db/phantom-vault/main/install.sh | PHANTOM_VERSION=v1.5.0 bash
#
# Installs both `phantom` and `vault-mcp` to /usr/local/bin (with sudo if
# needed) or to ~/.local/bin (no sudo, must already be on PATH).

set -euo pipefail

REPO="r-db/phantom-vault"
VERSION="${PHANTOM_VERSION:-latest}"

# --- Detect OS + arch ----------------------------------------------------------
uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s" in
  Darwin) os="macos" ;;
  Linux)  os="linux" ;;
  *) echo "ERROR: unsupported OS '$uname_s'. Phantom currently supports macOS and Linux." >&2; exit 1 ;;
esac

case "$uname_m" in
  arm64|aarch64) arch="arm64" ;;
  x86_64|amd64)  arch="x64" ;;
  *) echo "ERROR: unsupported arch '$uname_m'." >&2; exit 1 ;;
esac

# Linux arm64 is not yet built — flag it cleanly.
if [ "$os" = "linux" ] && [ "$arch" = "arm64" ]; then
  echo "ERROR: linux-arm64 is not yet a published build target." >&2
  echo "Build from source: git clone https://github.com/$REPO && cd phantom-vault && cargo build --release -p phantom-cli -p vault-mcp" >&2
  exit 1
fi

suffix="${os}-${arch}"

# --- Decide install location ---------------------------------------------------
if [ -w "/usr/local/bin" ]; then
  install_dir="/usr/local/bin"
  sudo_cmd=""
elif command -v sudo >/dev/null 2>&1 && [ "${PHANTOM_NO_SUDO:-0}" != "1" ]; then
  install_dir="/usr/local/bin"
  sudo_cmd="sudo"
else
  install_dir="$HOME/.local/bin"
  sudo_cmd=""
  mkdir -p "$install_dir"
  if ! echo ":$PATH:" | grep -q ":$install_dir:"; then
    needs_path_warning=1
  fi
fi

# --- Resolve the download URL --------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

phantom_url="$base/phantom-$suffix"
vault_mcp_url="$base/vault-mcp-$suffix"
sha_url="$base/SHA256SUMS-$suffix.txt"

# --- Download to a temp dir ----------------------------------------------------
tmp="$(mktemp -d -t phantom-install.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

echo "→ Downloading phantom-$suffix from $base ..."
curl --fail --location --silent --show-error --output "$tmp/phantom" "$phantom_url"
echo "→ Downloading vault-mcp-$suffix ..."
curl --fail --location --silent --show-error --output "$tmp/vault-mcp" "$vault_mcp_url"

# --- Verify checksums if available --------------------------------------------
if curl --fail --location --silent --show-error --output "$tmp/sums.txt" "$sha_url" 2>/dev/null; then
  echo "→ Verifying SHA256 checksums ..."
  cd "$tmp"
  # The published sums are computed on the suffixed names; rename for verify, then revert.
  mv phantom "phantom-$suffix"
  mv vault-mcp "vault-mcp-$suffix"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c sums.txt
  else
    sha256sum -c sums.txt
  fi
  mv "phantom-$suffix" phantom
  mv "vault-mcp-$suffix" vault-mcp
  cd - >/dev/null
else
  echo "→ Checksum file not published for this release — skipping verification."
fi

chmod +x "$tmp/phantom" "$tmp/vault-mcp"

# --- Install -------------------------------------------------------------------
echo "→ Installing to $install_dir ..."
$sudo_cmd mv "$tmp/phantom" "$install_dir/phantom"
$sudo_cmd mv "$tmp/vault-mcp" "$install_dir/vault-mcp"

# --- Done ----------------------------------------------------------------------
echo
echo "✓ Installed phantom + vault-mcp to $install_dir"
"$install_dir/phantom" --version

if [ "${needs_path_warning:-0}" = "1" ]; then
  # ANSI bold yellow if stdout is a terminal, plain otherwise
  if [ -t 1 ]; then YELLOW='\033[1;33m'; NC='\033[0m'; else YELLOW=''; NC=''; fi
  printf "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
  printf "${YELLOW}  ⚠  ACTION REQUIRED — $install_dir is NOT on your PATH${NC}\n"
  printf "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
  printf "${YELLOW}  Without this, 'phantom' won't be found.${NC}\n"
  printf "${YELLOW}  Add to your shell profile (~/.zshrc or ~/.bashrc):${NC}\n\n"
  printf "      ${YELLOW}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}\n\n"
  printf "${YELLOW}  Then run:  source ~/.zshrc   (or open a new terminal)${NC}\n\n"
fi

echo
echo "Next steps:"
echo "  phantom init                       Create a new vault"
echo "  phantom edit                       Open vault in \$EDITOR (encrypted notepad)"
echo "  phantom mcp install                Wire vault into Claude Code"
