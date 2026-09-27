# Wpn Agent

> Self-bootstrapping WireGuard node agent for the Wpn network.  Run it as root
> on a fresh VPS — it inspects the machine, installs WireGuard, configures
> `wg0` with NAT + forwarding, and serves a small HTTPS control API that the
> Wpn API calls to add/remove user peers.

**Zero npm dependencies — pure Node.js stdlib.  Requires Node.js 18+.**

---

## Quick start (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/Wizqdev/Wpn-Agent/main/install.sh | sudo bash
```

This single command:
1. Installs Node.js 18+ if missing (or upgrades an older version)
2. Clones the repo and deploys it to `/opt/wpn-agent`
3. Opens the required ports in `ufw` (if installed)
4. Registers and starts the `wpn-agent` systemd service

---

## From a local clone

```bash
git clone https://github.com/Wizqdev/Wpn-Agent.git
cd Wpn-Agent
sudo bash install.sh
```

Or run directly without installing as a service:

```bash
sudo node bin/wpn-agent
```

---

## First-run output

```
════════════════════════════════════════════════════════════
 Wpn node agent is live
   Agent URL:      https://<vps-ip>:44664
   Agent key:      <random token>
   Server pubkey:  <wireguard public key>
   WG endpoint:    <vps-ip>:51820/udp
════════════════════════════════════════════════════════════
 Add it:  Wpn Admin → Servers → label + URL + key.
```

Paste the **URL + key** in **Wpn Admin → Servers** — the node links instantly.

> **Cloud firewall:** open `udp/51820` and `tcp/44664` in your cloud provider's
> security group.  The agent handles `ufw` automatically, but cloud-level
> firewall rules are outside the box.

---

## CLI reference

| Command | Description |
|---|---|
| `node bin/wpn-agent` | Preflight → bootstrap WireGuard → serve control API |
| `node bin/wpn-agent --print` | Re-print Agent URL + key |
| `node bin/wpn-agent --install` | Deploy to `/opt/wpn-agent` + register systemd service |
| `node bin/wpn-agent --uninstall` | Remove the service (identity kept in `/etc/wpn-agent`) |
| `node bin/wpn-agent --skip-wg` | API only — skip WireGuard (dev smoke testing) |

---

## What happens on first run

The preflight check prints a full machine report before any changes are made:
distro, kernel, public IP, WAN interface, package manager, forwarding state,
and port availability.  Then the agent:

1. Installs `wireguard` via the detected package manager (apt/dnf/yum/pacman/zypper)
2. Generates the server keypair → `/etc/wireguard/server.key`
3. Writes `/etc/wireguard/wg0.conf` — subnet `10.66.0.1/24`, listen port 51820, NAT on WAN
4. Enables `net.ipv4.ip_forward` (+ v6) via `/etc/sysctl.d/99-wpn.conf`
5. Starts `wg-quick@wg0` (systemd) or falls back to `wg-quick up`
6. Creates `/etc/wpn-agent/` with `token` (0600), self-signed TLS cert, `server.pub`
7. Starts a UDP echo reflector on `udp/44665` (loss/jitter probe)
8. Optionally starts the wstunnel stealth relay on `tcp/443` or `tcp/8443`
9. Serves the control API on `tcp/44664` (HTTPS when cert available)

---

## Control API

All routes except `GET /health` require `Authorization: Bearer <agent-key>`.

| Route | Auth | Description |
|---|---|---|
| `GET /health` | — | Liveness probe (unauthenticated) |
| `GET /info` | ✓ | Server pubkey, endpoint, subnet, stealth state |
| `GET /stats` | ✓ | Peer counts, rx/tx bytes, system load |
| `GET /peers` | ✓ | List all peers (pubkey, endpoint, traffic, handshake) |
| `GET /peers/usage` | ✓ | Per-peer rx/tx/handshake for usage accounting |
| `POST /peers` | ✓ | `{ publicKey, address }` — add a peer |
| `DELETE /peers/:key` | ✓ | Remove a peer by public key |
| `GET /capabilities` | ✓ | Feature flags (stealth, echo port, wg version) |
| `POST /update` | ✓ | `git pull --ff-only` + systemd restart |
| `GET /speedtest` | — | Bandwidth probe (public, rate-limited to 4 req/min/IP, max 8 MiB) |

Peers are applied live (`wg set`) **and** persisted to `wg0.conf` so they
survive reboots.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `WPN_AGENT_PORT` | `44664` | Control API TCP port |
| `WPN_WG_PORT` | `51820` | WireGuard listen UDP port |
| `WPN_AGENT_DIR` | `/etc/wpn-agent` | Identity directory (token, TLS cert, pubkey) |
| `WPN_ECHO_PORT` | `44665` | UDP echo reflector port |
| `WPN_STEALTH` | *(auto)* | Set to `0` to disable the stealth relay entirely |
| `WPN_STEALTH_PORT` | *(auto)* | Override stealth port (default: 443, fallback 8443) |

---

## Security notes

- **Bearer token** — 192-bit random secret stored at `/etc/wpn-agent/token`
  (mode 0600).  Treat it like a password; rotate by deleting the file and
  restarting the agent.
- **TLS** — self-signed RSA-2048, 10-year cert.  The Wpn API skips cert
  verification but the bearer token authenticates every request using a
  constant-time comparison (`crypto.timingSafeEqual`).
- **Rate limiting** — 120 authenticated requests/minute per IP; `/speedtest`
  is additionally capped at 4 requests/minute with an 8 MiB payload ceiling.
- **Root required** — the agent must run as root to manage `wg0`, iptables
  NAT rules, and `sysctl` forwarding.
- **Stealth transport** — the pinned `wstunnel` binary is SHA-256 verified
  against both a hardcoded hash and the upstream `checksums.txt` before
  installation.

---

## Service management

```bash
# Logs
journalctl -u wpn-agent -f

# Status
systemctl status wpn-agent

# Restart
systemctl restart wpn-agent

# Re-print URL + key after service is running
node /opt/wpn-agent/bin/wpn-agent --print

# Upgrade (pulls latest from git + restarts)
curl -fsSL https://raw.githubusercontent.com/Wizqdev/Wpn-Agent/main/install.sh | sudo bash
```

---

## Repository

**GitHub:** https://github.com/Wizqdev/Wpn-Agent
