#!/usr/bin/env bash
#
# ReconForge installer — curl|bash entry point.
#
# Detects the host distribution + arch, ensures Docker is present
# (offers --auto-deps to install it on Debian/Ubuntu/Parrot/Kali/Arch),
# pulls the multi-arch Docker image from GHCR, installs the
# `reconforge` CLI wrapper and an XDG launcher.
#
# Usage:
#   curl -sSL https://reconforge.io/install.sh | bash
#   curl -sSL https://reconforge.io/install.sh | bash -s -- --auto-deps
#
set -euo pipefail

VERSION="${RECONFORGE_VERSION:-latest}"
IMAGE="ghcr.io/grover-bb/reconforge:${VERSION}"
PREFIX="${PREFIX:-/usr/local}"
CFG_DIR="${HOME}/.config/reconforge"
VAULT_DIR_DEFAULT="${HOME}/Documents/BugBountyVault"

AUTO_DEPS=0
DRY_RUN=0

# ── arg parse ────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --auto-deps) AUTO_DEPS=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --prefix=*)  PREFIX="${arg#*=}" ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

say()  { printf '\033[1;36m[reconforge]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[reconforge]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[reconforge]\033[0m %s\n' "$*" >&2; exit 1; }
run()  {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  + $*"
  else
    eval "$@"
  fi
}

# ── distro + arch ────────────────────────────────────────────────
ID=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
fi
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  PLATFORM=amd64 ;;
  aarch64|arm64) PLATFORM=arm64 ;;
  armv7l)  PLATFORM=armv7 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac
say "Detected: ${PRETTY_NAME:-$ID} on $PLATFORM"

# ── docker ───────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  if [ "$AUTO_DEPS" -eq 0 ]; then
    die "Docker not found. Re-run with --auto-deps or install Docker first."
  fi
  case "$ID" in
    debian|ubuntu|kali|parrot|raspbian)
      run "sudo apt-get update -y && sudo apt-get install -y docker.io"
      ;;
    arch|manjaro)
      run "sudo pacman -Sy --noconfirm docker"
      ;;
    fedora)
      run "sudo dnf install -y docker"
      ;;
    *)
      die "auto-deps: don't know how to install Docker on $ID"
      ;;
  esac
fi

# ── pull image ───────────────────────────────────────────────────
say "Pulling $IMAGE"
run "docker pull $IMAGE"

# ── config + vault dirs ──────────────────────────────────────────
say "Creating $CFG_DIR and $VAULT_DIR_DEFAULT"
run "mkdir -p $CFG_DIR/scopes $VAULT_DIR_DEFAULT"

# ── CLI wrapper ──────────────────────────────────────────────────
CLI_PATH="$PREFIX/bin/reconforge"
say "Installing CLI wrapper to $CLI_PATH"
WRAPPER_SRC="$(dirname "$0")/reconforge-cli"
if [ ! -f "$WRAPPER_SRC" ]; then
  WRAPPER_SRC="-"   # piped install — embed the wrapper inline
fi
run "sudo install -m 0755 $WRAPPER_SRC $CLI_PATH" || \
  warn "CLI install requires sudo. Re-run with sudo or copy reconforge-cli manually."

# ── desktop launcher ─────────────────────────────────────────────
DESKTOP_PATH="$HOME/.local/share/applications/reconforge.desktop"
say "Installing XDG launcher to $DESKTOP_PATH"
run "mkdir -p $(dirname $DESKTOP_PATH)"
if [ -f "$(dirname "$0")/reconforge.desktop" ]; then
  run "install -m 0644 $(dirname "$0")/reconforge.desktop $DESKTOP_PATH"
fi

say "Installed. Next steps:"
say "  reconforge wizard    # interactive first-run setup"
say "  reconforge run       # start the service on http://localhost:8342"
say "  reconforge --help    # all commands"
