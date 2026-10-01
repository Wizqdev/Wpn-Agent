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
#  All WPN_* env overrides are honoured (e.g. WPN_AGENT_PORT=5000 bash install.sh).
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
# Port configuration — mirrors the agent's env vars so the firewall holes we
# open match what the agent will actually bind.
# ---------------------------------------------------------------------------
AGENT_PORT="${WPN_AGENT_PORT:-44664}"
WG_PORT="${WPN_WG_PORT:-51820}"
ECHO_PORT="${WPN_ECHO_PORT:-44665}"
STEALTH_PORT="${WPN_STEALTH_PORT:-443}"
STEALTH_PORT2=8443   # agent fallback when 443 is taken

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  log_err "this script must be run as root (sudo bash install.sh)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Package install helper — covers every manager the agent itself supports.
# ---------------------------------------------------------------------------
pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q "$@"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --needed "$@"
  elif command -v zypper >/dev/null 2>&1; then
    zypper -n install "$@"
  else
    return 1
  fi
}

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

  if ! pkg_install nodejs; then
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
    pkg_install git || { log_err "git not found — install it manually"; exit 1; }
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
  # Copy the whole tree including .git so POST /update can fast-forward later.
  cp -a "$SRC/." "$DEST/"
  chmod +x "$DEST/bin/wpn-agent"
  log_ok "agent deployed to ${DEST}"
fi

# ---------------------------------------------------------------------------
# Firewall — open required ports in ufw (if available)
# ---------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${AGENT_PORT}/tcp"   >/dev/null || true   # control API
  ufw allow "${WG_PORT}/udp"      >/dev/null || true   # WireGuard
  ufw allow "${STEALTH_PORT}/tcp" >/dev/null || true   # stealth relay (wss)
  ufw allow "${STEALTH_PORT2}/tcp">/dev/null || true   # stealth fallback
  ufw allow "${ECHO_PORT}/udp"    >/dev/null || true   # UDP echo probe
  log_ok "ufw rules added (${AGENT_PORT}/tcp, ${WG_PORT}/udp, ${STEALTH_PORT}/tcp, ${STEALTH_PORT2}/tcp, ${ECHO_PORT}/udp)"
fi

# ---------------------------------------------------------------------------
# Create identity + show the operator their URL + key
# ---------------------------------------------------------------------------
# --print runs BEFORE --install so identity material exists before the service
# starts — avoids a create-vs-create race between the CLI and the daemon.
node "${DEST}/bin/wpn-agent" --print || true

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
log_info "  Remember to open udp/${WG_PORT} and tcp/${AGENT_PORT} in your cloud"
log_info "  provider's security group / firewall policy."
