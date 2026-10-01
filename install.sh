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

NODE_MIN=22

fetch_script() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$1"
  else
    log_err "neither curl nor wget found — install Node.js ${NODE_MIN}+ manually"
    exit 1
  fi
}

install_node() {
  log_info "installing Node.js ${NODE_MIN}.x…"
  if command -v apt-get >/dev/null 2>&1; then
    fetch_script "https://deb.nodesource.com/setup_${NODE_MIN}.x" | bash -
    pkg_install nodejs
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    fetch_script "https://rpm.nodesource.com/setup_${NODE_MIN}.x" | bash -
    pkg_install nodejs
  elif command -v pacman >/dev/null 2>&1; then
    pkg_install nodejs npm
  elif command -v zypper >/dev/null 2>&1; then
    pkg_install "nodejs${NODE_MIN}"
  else
    log_err "no supported package manager — install Node.js ${NODE_MIN}+ manually"
    exit 1
  fi
}

node_major() {
  node -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo 0
}

if ! command -v node >/dev/null 2>&1 || [[ "$(node_major)" -lt "$NODE_MIN" ]]; then
  if command -v node >/dev/null 2>&1; then
    log_warn "Node.js $(node_major) is too old — upgrading to ${NODE_MIN}.x"
  fi
  install_node
fi

if [[ "$(node_major)" -lt "$NODE_MIN" ]]; then
  log_err "Node.js ${NODE_MIN}+ is required but $(node --version 2>/dev/null || echo 'none') is installed"
  exit 1
fi

log_ok "node $(node --version)"

is_agent_tree() {
  [[ -f "$1/bin/wpn-agent" && -f "$1/src/agent.js" ]]
}

SRC=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  CANDIDATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if is_agent_tree "$CANDIDATE"; then
    SRC="$CANDIDATE"
  fi
fi

if [[ -z "$SRC" ]]; then
  REPO_URL="${WPN_REPO_URL:-https://github.com/Wizqdev/Wpn-Agent.git}"
  CLONE_DIR="$(mktemp -d)"
  trap 'rm -rf "$CLONE_DIR"' EXIT
  log_info "no agent source next to this script — cloning ${REPO_URL}…"
  if ! command -v git >/dev/null 2>&1; then
    pkg_install git || { log_err "git not found — install it manually"; exit 1; }
  fi
  git clone --depth 1 "$REPO_URL" "$CLONE_DIR"
  if ! is_agent_tree "$CLONE_DIR"; then
    log_err "cloned repository is missing bin/wpn-agent or src/agent.js"
    exit 1
  fi
  SRC="$CLONE_DIR"
fi

DEST="/opt/wpn-agent"
if [[ "$SRC" != "$DEST" ]]; then
  STAGE="${DEST}.new"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  cp -a "$SRC/." "$STAGE/"
  if ! is_agent_tree "$STAGE"; then
    rm -rf "$STAGE"
    log_err "staged copy is incomplete — leaving ${DEST} untouched"
    exit 1
  fi
  if [[ -f "$DEST/bin/wstunnel" ]]; then
    cp -a "$DEST/bin/wstunnel" "$STAGE/bin/wstunnel"
  fi
  chmod +x "$STAGE/bin/wpn-agent"
  rm -rf "${DEST}.old"
  [[ -d "$DEST" ]] && mv "$DEST" "${DEST}.old"
  mv "$STAGE" "$DEST"
  rm -rf "${DEST}.old"
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
