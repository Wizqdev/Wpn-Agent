#!/usr/bin/env bash
# =============================================================================
#  Wpn Agent — one-shot installer
#  https://github.com/Wizqdev/Wpn-Agent
#
#  Usage (run as root on a fresh VPS):
#
#    # From a local clone:
#    sudo bash install.sh
#
#    # Directly from GitHub (one-liner):
#    curl -fsSL https://raw.githubusercontent.com/Wizqdev/Wpn-Agent/main/install.sh | sudo bash
#
#  The script is fully idempotent — safe to re-run for upgrades.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_GRN='\033[0;32m'; C_YLW='\033[0;33m'
  C_RED='\033[0;31m'; C_RST='\033[0m'
else
  C_GRN=''; C_YLW=''; C_RED=''; C_RST=''
fi

log_ok()   { echo -e "${C_GRN}[✓]${C_RST} $*"; }
log_info() { echo -e "    $*"; }
log_warn() { echo -e "${C_YLW}[!]${C_RST} $*"; }
log_err()  { echo -e "${C_RED}[✗]${C_RST} $*" >&2; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  log_err "this script must be run as root (sudo bash install.sh)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Node.js — install if missing, upgrade via NodeSource if too old
# ---------------------------------------------------------------------------
NODE_MIN=18

install_node() {
  log_info "installing Node.js ${NODE_MIN}.x via NodeSource…"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MIN}.x" | bash -
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "https://deb.nodesource.com/setup_${NODE_MIN}.x" | bash -
  else
    log_err "neither curl nor wget found — install Node.js ${NODE_MIN}+ manually"
    exit 1
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq nodejs
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nodejs
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q nodejs
  else
    log_err "no supported package manager — install Node.js ${NODE_MIN}+ manually"
    exit 1
  fi
}

if ! command -v node >/dev/null 2>&1; then
  install_node
fi

NODE_MAJOR="$(node -e 'process.stdout.write(process.versions.node.split(".")[0])')"
if [[ "$NODE_MAJOR" -lt "$NODE_MIN" ]]; then
  log_warn "Node.js ${NODE_MAJOR} is too old — upgrading to ${NODE_MIN}.x"
  install_node
fi

log_ok "node $(node --version)"

# ---------------------------------------------------------------------------
# Resolve source directory
# ---------------------------------------------------------------------------
# Works whether the script is executed from a local clone or piped from curl.
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" ]]; then
  SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  # Piped from curl — clone the repo into a temp directory.
  REPO_URL="https://github.com/Wizqdev/Wpn-Agent.git"
  CLONE_DIR="$(mktemp -d)"
  log_info "piped install detected — cloning ${REPO_URL}…"
  if ! command -v git >/dev/null 2>&1; then
    apt-get install -y -qq git 2>/dev/null \
      || dnf install -y -q git 2>/dev/null \
      || yum install -y -q git 2>/dev/null \
      || { log_err "git not found — install it manually"; exit 1; }
  fi
  git clone --depth 1 "$REPO_URL" "$CLONE_DIR"
  SRC="$CLONE_DIR"
fi

# ---------------------------------------------------------------------------
# Deploy to /opt/wpn-agent
# ---------------------------------------------------------------------------
DEST="/opt/wpn-agent"
if [[ "$SRC" != "$DEST" ]]; then
  mkdir -p "$DEST"
  cp -r "$SRC/src" "$SRC/bin" "$SRC/package.json" "$DEST/"
  # Make the entrypoint executable.
  chmod +x "$DEST/bin/wpn-agent"
  log_ok "agent deployed to ${DEST}"
fi

# ---------------------------------------------------------------------------
# Firewall — open required ports in ufw (if available)
# ---------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  ufw allow 44664/tcp >/dev/null || true   # control API
  ufw allow 51820/udp >/dev/null || true   # WireGuard
  ufw allow 443/tcp   >/dev/null || true   # stealth relay (wstunnel wss)
  ufw allow 8443/tcp  >/dev/null || true   # stealth fallback
  ufw allow 44665/udp >/dev/null || true   # UDP echo probe
  log_ok "ufw rules added (44664/tcp, 51820/udp, 443/tcp, 8443/tcp, 44665/udp)"
fi

# ---------------------------------------------------------------------------
# Install + start the systemd service
# ---------------------------------------------------------------------------
node "${DEST}/bin/wpn-agent" --install

echo
log_ok "done — the agent is running as systemd service 'wpn-agent'"
log_info ""
log_info "  Get URL + key:  node ${DEST}/bin/wpn-agent --print"
log_info "  Follow logs:    journalctl -u wpn-agent -f"
log_info "  Service status: systemctl status wpn-agent"
log_info ""
log_info "  Remember to open udp/51820 and tcp/44664 in your cloud"
log_info "  provider's security group / firewall policy."
