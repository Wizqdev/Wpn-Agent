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
   TLS sha256:     <cert fingerprint — pin this in the API>
════════════════════════════════════════════════════════════
 Add it:  Wpn Admin → Servers → label + URL + key.
```

(When running under systemd the key line is redacted — `wpn-agent --print`
reveals it interactively.)

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
| `node bin/wpn-agent --uninstall` | Remove the service **and** tear down the data plane (wg0, NAT, sysctl, stealth). Identity + WG server key kept in `/etc/wpn-agent` + `/etc/wireguard` |
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
| `POST /peers` | ✓ | `{ publicKey, address }` — add a peer (address must be inside the node subnet, not the server IP, not already claimed) |
| `DELETE /peers` | ✓ | `{ publicKey }` — remove a peer (body form; simplest) |
| `DELETE /peers/:key` | ✓ | Remove a peer by public key — **URL-encode the key** (`encodeURIComponent`); base64 keys may contain `/` and `=` |
| `GET /capabilities` | ✓ | Feature flags (stealth, echo port, wg version) |
| `POST /update` | ✓ | Fast-forward update + restart — **disabled by default**; requires `WPN_ALLOW_REMOTE_UPDATE=1` (optionally `WPN_UPDATE_REQUIRE_SIGNED=1` to verify the upstream commit) |
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
| `WPN_WG_IFACE` | `wg0` | WireGuard interface name |
| `WPN_SUBNET_V4` | `10.66.0.1/24` | Tunnel IPv4 subnet (server address/prefix) |
| `WPN_SUBNET_V6` | `fd00:66::1/64` | Tunnel IPv6 subnet |
| `WPN_LOG_JSON` | `0` | Set to `1` for newline-delimited JSON logs |
| `WPN_ALLOW_REMOTE_UPDATE` | `0` | Set to `1` to enable `POST /update` (root-level code update — off by default) |
| `WPN_UPDATE_REQUIRE_SIGNED` | `0` | Set to `1` to require `git verify-commit` on the fetched commit before merging |

On systemd installs, put overrides in `/etc/wpn-agent/agent.env`
(`EnvironmentFile=` is wired into the unit), then `systemctl restart wpn-agent`.

---

## Security notes

- **Bearer token** — 192-bit random secret stored at `/etc/wpn-agent/token`
  (mode 0600).  Treat it like a password; rotate by deleting the file and
  restarting the agent.  The token is redacted from journal logs — reveal it
  interactively with `wpn-agent --print`.
- **TLS + pinning** — self-signed RSA-2048, 10-year cert.  Because it is
  self-signed, the Wpn API should pin the certificate fingerprint
  (`GET /info` → `tlsFingerprint`, also printed in the first-run banner)
  instead of disabling verification — pinning is what stops a MITM from
  terminating TLS and stealing the bearer token.  Requests authenticate via
  `crypto.timingSafeEqual`.
- **Peer validation** — `POST /peers` rejects malformed keys/addresses,
  addresses outside the tunnel subnet, the server's own address, and IPs
  already claimed by another peer (checked against both the live interface
  and `wg0.conf`).  Claim-check, `wg set`, and config persist run inside a
  single mutex so concurrent requests cannot double-assign a tunnel IP; a
  conflict returns `409` rather than a generic error.
- **Config durability** — `wg0.conf` writes are atomic (temp file, fsync,
  rename, dir fsync), and a persist failure rolls back the live `wg set`
  so runtime state and on-disk state never silently diverge.
- **Rate limiting** — 120 authenticated requests/minute per IP; `/speedtest`
  is additionally capped at 4 requests/minute with an 8 MiB payload ceiling;
  the UDP echo reflector drops packets over 64 B and 200 pps per source so it
  cannot be abused as an amplifier.
- **MSS clamping** — PostUp applies TCPMSS `--clamp-mss-to-pmtu` on forwarded
  TCP so clients behind PPPoE/low-MTU links don't hit TLS hangs.
- **Root required** — the agent must run as root to manage `wg0`, iptables
  NAT rules, and `sysctl` forwarding.
- **Stealth transport** — the pinned `wstunnel` binary is SHA-256 verified
  against both a hardcoded hash and the upstream `checksums.txt` before
  installation.
- **Audit trail** — peer add/remove operations are logged with source IP and
  (truncated) pubkey via the agent log; failed auth attempts are logged with
  source IP; update attempts are audited with before/after commit hashes.
- **Remote update off by default** — `POST /update` performs a root-level
  `git pull` + restart, so it returns `403` unless the operator opts in with
  `WPN_ALLOW_REMOTE_UPDATE=1`; `WPN_UPDATE_REQUIRE_SIGNED=1` additionally
  requires the fetched commit to pass `git verify-commit` before merging.

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
