#!/usr/bin/env bash
# Wpn agent installer — run as root on a fresh VPS.
#
#   git clone <repo> && cd Wpn-Agent && sudo bash install.sh
#   or:  curl -fsSL <raw-url>/install.sh | sudo bash
#
# Installs Node.js if missing, copies the agent to /opt/wpn-agent,
# and registers + starts the systemd service. The agent itself does
# the WireGuard bootstrap on first start and prints URL + key.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

# --- node -------------------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "[*] installing Node.js…"
  if command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y -qq nodejs
  elif command -v dnf >/dev/null; then
    dnf install -y -q nodejs
  elif command -v yum >/dev/null; then
    yum install -y -q nodejs
  else
    echo "[✗] no supported package manager — install Node.js 18+ manually"; exit 1
  fi
fi

MAJOR="$(node -e 'console.log(process.versions.node.split(".")[0])')"
if [[ "$MAJOR" -lt 18 ]]; then
  echo "[✗] Node $MAJOR is too old — install Node.js 18+"; exit 1
fi
echo "[✓] node $(node --version)"

# --- deploy -----------------------------------------------------------------
SRC="$(cd "$(dirname "$0")" && pwd)"
if [[ "$SRC" != /opt/wpn-agent ]]; then
  mkdir -p /opt/wpn-agent
  cp -r "$SRC/src" "$SRC/bin" "$SRC/package.json" /opt/wpn-agent/
fi

# --- firewall — open control, wireguard, stealth + echo ports ----------------
if command -v ufw >/dev/null 2>&1; then
  ufw allow 44664/tcp >/dev/null || true   # control API
  ufw allow 51820/udp >/dev/null || true   # wireguard
  ufw allow 443/tcp >/dev/null || true     # stealth relay (wstunnel wss)
  ufw allow 8443/tcp >/dev/null || true    # stealth fallback port
  ufw allow 44665/udp >/dev/null || true   # udp echo probe
  echo "[✓] ufw rules added (control 44664, wg 51820, stealth 443/8443, echo 44665)"
fi

node /opt/wpn-agent/bin/wpn-agent --install
echo
echo "[✓] done. The agent is running — get your URL + key with:"
echo "      node /opt/wpn-agent/bin/wpn-agent --print"
echo "    or:  journalctl -u wpn-agent -n 30"
