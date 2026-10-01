# Wpn Agent — agent notes

Self-bootstrapping WireGuard node agent. Zero npm dependencies (pure Node.js
stdlib), Node 22+ required, must run as root on Linux.

## Commands

- `npm test` — run the test suite (`node --test test/*.test.js`)
- `npm run dev` — run the API only, skipping WireGuard (`--skip-wg`); set
  `WPN_AGENT_DIR=/tmp/wpn-agent` to run unprivileged
- `sudo node bin/wpn-agent` — full run: preflight → WG bootstrap → control API
- `sudo node bin/wpn-agent --print` — print agent URL + key (no bootstrap)
- `sudo bash install.sh` — idempotent install to `/opt/wpn-agent` + systemd

## Conventions

- CommonJS `"use strict"`. Source files intentionally carry **no comments**
  — keep them comment-free (no `//`, `/* */`, or JSDoc blocks).
- All system calls are **async** via `util.runBin` (arg arrays, no shell —
  preferred) or `util.run` (shell string, only when pipes/redirects needed).
  Never `execSync`/`execFileSync` — they block the event loop.
- `wg0.conf` mutations must go through `confLock` (`src/lock.js`) and the
  pure helpers `upsertPeerConf` / `removePeerFromConf` in `src/wireguard.js`.
  `addPeer`/`removePeer` hold the lock across the full validate → `wg set` →
  persist sequence and roll back the live change if the persist fails; the
  conf write itself is atomic (temp file + fsync + rename).
- Firewall rules live in `src/firewall.js` as fragments with detection `key`s;
  iptables and nftables (`inet wpn` table) backends must stay in sync.
- Files under `/etc/wpn-agent` are identity material — never delete them on
  uninstall; the data plane (wg0, NAT rules, sysctl drop-in) is torn down.
- The bearer token must never be written to journald — banner redacts it when
  stdout isn't a TTY; `--print` reveals it.

## Key invariants

- `wg show <iface> dump` emits 8-field peer lines; `wg show all dump` emits
  9-field (iface-prefixed) lines — `_parseDump` handles both.
- Peer addresses must be inside `WPN_SUBNET_V4`/`WPN_SUBNET_V6` and not equal
  to the server address — enforced by `addrInSubnet` in `addPeer`.
- `POST /update` is disabled unless `WPN_ALLOW_REMOTE_UPDATE=1`; signed
  upstream commits can be required with `WPN_UPDATE_REQUIRE_SIGNED=1`.
- `systemd/wpn-agent.service` is generated from the template in
  `src/service.js` — run `npm run gen:unit` after changing it (a test fails
  on drift).
- wstunnel is pinned by version + SHA-256; bump `WST_VERSION` deliberately.
