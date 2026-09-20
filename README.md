# Wpn Agent

Self-bootstrapping WireGuard node agent for the Wpn network. Run it as root on
a fresh VPS — it inspects the machine, installs WireGuard, configures `wg0`
with NAT + forwarding, and serves a small HTTPS control API that the Wpn Api
calls to add/remove user peers.

Zero npm dependencies — pure Node.js stdlib. Requires Node 18+.

## Quick start (VPS)

```bash
git clone <this-repo> && cd Wpn-Agent
sudo bash install.sh          # installs Node if needed, copies to /opt, systemd
```

Or run it directly:

```bash
sudo node bin/wpn-agent
```

On first run you'll get:

```
════════════════════════════════════════════════════════════
 Wpn node agent is live
   Agent URL:      https://<vps-ip>:44664
   Agent key:      <random token>
   Server pubkey:  <wireguard public key>
   WG endpoint:    <vps-ip>:51820/udp
════════════════════════════════════════════════════════════
```

Paste the **URL + key** in **Wpn Admin → Servers** on the website — the node
links instantly.

> Open `udp/51820` and `tcp/44664` in your cloud provider's firewall
> (the agent opens them in ufw automatically, but cloud security groups are
> managed outside the box).

## Commands

| Command | What it does |
|---|---|
| `node bin/wpn-agent` | preflight → bootstrap WireGuard → serve API |
| `node bin/wpn-agent --print` | re-print Agent URL + key |
| `node bin/wpn-agent --install` | copy to `/opt/wpn-agent` + systemd service |
| `node bin/wpn-agent --uninstall` | remove the service (keeps identity) |
| `node bin/wpn-agent --skip-wg` | API only, don't touch WireGuard (dev) |

## What it does on first run

Preflight prints a report before changing anything: distro, kernel, public IP,
WAN interface, package manager, forwarding state, port availability. Then:

1. Installs `wireguard` via the detected package manager (apt/dnf/yum/pacman/zypper)
2. Generates the server keypair → `/etc/wireguard/server.key`
3. Writes `/etc/wireguard/wg0.conf` — `10.66.0.1/24`, `ListenPort 51820`, NAT on the WAN iface
4. Enables `net.ipv4.ip_forward` (+ v6) via `/etc/sysctl.d/99-wpn.conf`
5. Starts `wg-quick@wg0` (systemd) or `wg-quick up`
6. Creates `/etc/wpn-agent/` — `token` (0600), self-signed TLS cert, `server.pub`
7. Serves the control API on `tcp/44664`

## Control API

All routes except `GET /health` require `Authorization: Bearer <agent key>`.

| Route | Purpose |
|---|---|
| `GET /health` | liveness (unauthenticated) |
| `GET /info` | server pubkey, endpoint, subnet — used when linking |
| `GET /stats` | peer counts, rx/tx bytes, node load |
| `GET /peers` | list peers (pubkey, allowed IPs, handshake, traffic) |
| `POST /peers` | `{publicKey, address}` — add a peer |
| `DELETE /peers/:key` | remove a peer |

Peers are applied live (`wg set`) and persisted to `wg0.conf` so they survive
reboots.

## Environment

| Var | Default | Meaning |
|---|---|---|
| `WPN_AGENT_PORT` | `44664` | control API port (tcp) |
| `WPN_WG_PORT` | `51820` | WireGuard listen port (udp) |
| `WPN_AGENT_DIR` | `/etc/wpn-agent` | identity directory |

## Security notes

- The agent key is a random 192-bit bearer token stored `0600` at
  `/etc/wpn-agent/token` — treat it like a password.
- TLS is self-signed; the Wpn Api disables cert verification but the bearer key
  still authenticates every request (timing-safe comparison).
- Rate limit: 120 authed requests/minute per IP.
- The agent must run as root — it owns `wg0`, iptables NAT, and sysctl.
