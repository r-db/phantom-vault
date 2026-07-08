#!/usr/bin/env bash
# Phantom Vault — one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/r-db/phantom-vault/main/install.sh | bash
#
# Or pin to a version:
#   curl -fsSL https://raw.githubusercontent.com/r-db/phantom-vault/main/install.sh | PHANTOM_VERSION=v0.1.0 bash
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
# Goal: zero-touch UX. After install, `phantom` must work in the SAME terminal
# the user pasted the curl one-liner into. That rules out anything that needs a
# new shell or a manual `source`. /usr/local/bin is in macOS default PATH
# (/etc/paths) and in every Linux default PATH, so installing there means
# `phantom` is callable immediately — no PATH edits, no new terminal.
#
# Priority — pick the first that gives zero-touch UX, falling back to sudo only
# when no in-PATH writable directory exists:
#   1. /usr/local/bin   writable (no sudo)        Intel Macs / pre-existing perms
#   2. /opt/homebrew/bin writable (no sudo)       Apple Silicon Homebrew users
#   3. /usr/local/bin via sudo (creates if needed) one-time password prompt
#   4. ~/.local/bin                                PHANTOM_NO_SUDO=1 / no tty
#
# Note on sudo + curl|bash: sudo reads the password from /dev/tty, not stdin.
# So even when this script is piped from curl, sudo prompts work correctly
# as long as the user's terminal is attached.

# PHANTOM_NO_SUDO=1 means "user scope, no system writes at all" — go straight
# to ~/.local/bin regardless of what other directories happen to be writable.
if [ "${PHANTOM_NO_SUDO:-0}" = "1" ]; then
  install_dir="$HOME/.local/bin"
  sudo_cmd=""
  mkdir -p "$install_dir"
  if ! echo ":$PATH:" | grep -q ":$install_dir:"; then
    needs_path_warning=1
  fi
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
  install_dir="/usr/local/bin"
  sudo_cmd=""
elif [ -d "/opt/homebrew/bin" ] && [ -w "/opt/homebrew/bin" ]; then
  # Homebrew on Apple Silicon — already on default PATH, no sudo needed.
  install_dir="/opt/homebrew/bin"
  sudo_cmd=""
elif command -v sudo >/dev/null 2>&1 && { [ -t 0 ] || [ -t 1 ]; }; then
  install_dir="/usr/local/bin"
  sudo_cmd="sudo"
  if [ ! -d "$install_dir" ]; then
    echo "→ /usr/local/bin doesn't exist yet — creating it (one-time, requires sudo)..."
    sudo mkdir -p "$install_dir"
    sudo chmod 0755 "$install_dir"
  fi
  echo "→ Installing to /usr/local/bin (system PATH) — sudo password may be required..."
  sudo -v
else
  # No tty + no sudo: fall back to user scope.
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
if [ -t 1 ]; then GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'; else GREEN=''; BOLD=''; NC=''; fi
printf "${GREEN}✓ Installed phantom + vault-mcp to $install_dir${NC}\n"
"$install_dir/phantom" --version
# Confirm the binary is callable from THIS shell, not just present on disk.
if echo ":$PATH:" | grep -q ":$install_dir:" && command -v phantom >/dev/null 2>&1; then
  printf "\n${BOLD}phantom is ready. Type:${NC}  phantom\n\n"
fi

if [ "${needs_path_warning:-0}" = "1" ]; then
  # Auto-append the PATH line to the user's shell config so they don't have
  # to do it manually. Pattern follows rustup, volta, nvm, etc.
  shell_name="$(basename "${SHELL:-/bin/zsh}")"
  case "$shell_name" in
    zsh)
      rc_file="$HOME/.zshrc"
      path_line='export PATH="$HOME/.local/bin:$PATH"'
      ;;
    bash)
      # macOS reads ~/.bash_profile for login shells; Linux uses ~/.bashrc.
      if [ "$(uname -s)" = "Darwin" ] && [ -f "$HOME/.bash_profile" ]; then
        rc_file="$HOME/.bash_profile"
      else
        rc_file="$HOME/.bashrc"
      fi
      path_line='export PATH="$HOME/.local/bin:$PATH"'
      ;;
    fish)
      rc_file="$HOME/.config/fish/config.fish"
      mkdir -p "$(dirname "$rc_file")"
      path_line='set -gx PATH "$HOME/.local/bin" $PATH'
      ;;
    *)
      rc_file="$HOME/.profile"
      path_line='export PATH="$HOME/.local/bin:$PATH"'
      ;;
  esac

  # Don't duplicate — check if the line (or any reference to ~/.local/bin) is already there
  if [ -f "$rc_file" ] && grep -q '\.local/bin' "$rc_file" 2>/dev/null; then
    auto_added=0
  else
    {
      echo ""
      echo "# Added by Phantom Vault installer ($(date +%Y-%m-%d))"
      echo "$path_line"
    } >> "$rc_file"
    auto_added=1
  fi

  # ANSI green if stdout is a terminal, plain otherwise
  if [ -t 1 ]; then GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'; else GREEN=''; YELLOW=''; BOLD=''; NC=''; fi

  if [ "$auto_added" = "1" ]; then
    printf "\n${GREEN}✓ Added ${install_dir} to your PATH in ${rc_file}${NC}\n\n"
    printf "${BOLD}To use 'phantom' right now:${NC}\n"
    printf "  source $rc_file\n\n"
    printf "${BOLD}Or just open a new terminal — phantom is ready.${NC}\n\n"
  else
    printf "\n${YELLOW}Note: ${install_dir} is already referenced in ${rc_file}.${NC}\n"
    printf "${YELLOW}If 'phantom' isn't found, restart your shell or run:  source ${rc_file}${NC}\n\n"
  fi
fi

echo
echo "Next steps:"
echo "  phantom init                       Create a new vault"
echo "  phantom edit                       Open vault in \$EDITOR (encrypted notepad)"
echo "  phantom mcp install                Wire vault into Claude Code"
