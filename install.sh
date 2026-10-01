#!/usr/bin/env bash

set -euo pipefail

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

AGENT_PORT="${WPN_AGENT_PORT:-44664}"
WG_PORT="${WPN_WG_PORT:-51820}"
ECHO_PORT="${WPN_ECHO_PORT:-44665}"
STEALTH_PORT="${WPN_STEALTH_PORT:-443}"
STEALTH_PORT2=8443

if [[ $EUID -ne 0 ]]; then
  log_err "this script must be run as root (sudo bash install.sh)"
  exit 1
fi

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

if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" ]]; then
  SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  REPO_URL="https://github.com/Wizqdev/Wpn-Agent.git"
  CLONE_DIR="$(mktemp -d)"
  log_info "piped install detected — cloning ${REPO_URL}…"
  if ! command -v git >/dev/null 2>&1; then
    pkg_install git || { log_err "git not found — install it manually"; exit 1; }
  fi
  git clone --depth 1 "$REPO_URL" "$CLONE_DIR"
  SRC="$CLONE_DIR"
fi

DEST="/opt/wpn-agent"
if [[ "$SRC" != "$DEST" ]]; then
  mkdir -p "$DEST"
  cp -a "$SRC/." "$DEST/"
  chmod +x "$DEST/bin/wpn-agent"
  log_ok "agent deployed to ${DEST}"
fi

if command -v ufw >/dev/null 2>&1; then
  ufw allow "${AGENT_PORT}/tcp"   >/dev/null || true
  ufw allow "${WG_PORT}/udp"      >/dev/null || true
  ufw allow "${STEALTH_PORT}/tcp" >/dev/null || true
  ufw allow "${STEALTH_PORT2}/tcp">/dev/null || true
  ufw allow "${ECHO_PORT}/udp"    >/dev/null || true
  log_ok "ufw rules added (${AGENT_PORT}/tcp, ${WG_PORT}/udp, ${STEALTH_PORT}/tcp, ${STEALTH_PORT2}/tcp, ${ECHO_PORT}/udp)"
fi

node "${DEST}/bin/wpn-agent" --print || true

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
