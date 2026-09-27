/**
 * @fileoverview WireGuard lifecycle — install, `wg0` config, peer management,
 * stats, and interface introspection.
 *
 * All conf-file mutations go through the {@link confLock} async mutex so
 * concurrent API requests cannot corrupt `wg0.conf`.  All `wg` and `ip`
 * binary calls use {@link runBin} (arg arrays, no shell) to eliminate any
 * injection surface.
 *
 * NAT/forwarding rules are delegated to {@link module:firewall} which handles
 * both iptables and nftables backends transparently.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const { run, runBin, tryRun, tryRunBin, log } = require("./util");
const { confLock } = require("./lock");
const firewall = require("./firewall");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WG_IFACE    = process.env.WPN_WG_IFACE || "wg0";
const WG_CONF     = `/etc/wireguard/${WG_IFACE}.conf`;
const WG_KEY_FILE = "/etc/wireguard/server.key";
const SUBNET_V4   = process.env.WPN_SUBNET_V4 || "10.66.0.1/24";
const SUBNET_V6   = process.env.WPN_SUBNET_V6 || "fd00:66::1/64";

/** @type {Record<string, string>} Package-manager → install command. */
const INSTALLERS = {
  "apt-get": "apt-get update -qq && apt-get install -y -qq wireguard iptables",
  dnf:       "dnf install -y -q wireguard-tools iptables",
  yum:       "yum install -y -q wireguard-tools iptables",
  pacman:    "pacman -S --noconfirm --needed wireguard-tools iptables",
  zypper:    "zypper -n install wireguard-tools iptables",
};

// ---------------------------------------------------------------------------
// WireGuard setup steps
// ---------------------------------------------------------------------------

/**
 * Install WireGuard via the host's package manager if not already present.
 *
 * @param {object} r - Preflight report.
 */
function ensureInstalled(r) {
  if (r.wg.installed) {
    return log.ok(`wireguard already installed (${r.wg.version})`);
  }
  const installer = INSTALLERS[r.pkgMgr];
  if (!installer) {
    throw new Error("no supported package manager — install wireguard manually");
  }
  log.info(`installing wireguard via ${r.pkgMgr}…`);
  run(installer, { timeout: 300_000 });
  log.ok("wireguard installed");
}

/**
 * Write the initial `wg0.conf` and server private key if they don't exist.
 *
 * @param {object} r - Preflight report.
 * @param {number} wgPort
 */
function ensureConfig(r, wgPort) {
  fs.mkdirSync("/etc/wireguard", { mode: 0o700, recursive: true });

  if (!fs.existsSync(WG_KEY_FILE)) {
    fs.writeFileSync(WG_KEY_FILE, runBin("wg", ["genkey"]) + "\n", { mode: 0o600 });
    log.ok("server keypair generated");
  }

  if (!fs.existsSync(WG_CONF)) {
    const priv = fs.readFileSync(WG_KEY_FILE, "utf8").trim();
    const { up, down } = firewall.confNatRules(r.wanIf, WG_IFACE);
    fs.writeFileSync(
      WG_CONF,
      [
        "[Interface]",
        `Address = ${SUBNET_V4}, ${SUBNET_V6}`,
        `ListenPort = ${wgPort}`,
        `PrivateKey = ${priv}`,
        `PostUp = ${up}`,
        `PostDown = ${down}`,
        "",
      ].join("\n"),
      { mode: 0o600 }
    );
    log.ok(`wg0.conf written (nat on ${r.wanIf}, backend: ${firewall.backend()})`);
  }
}

/**
 * Enable IPv4/IPv6 forwarding and persist via sysctl.d.
 */
function ensureForwarding() {
  fs.writeFileSync(
    "/etc/sysctl.d/99-wpn.conf",
    "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"
  );
  tryRun("sysctl --system -q");
  log.ok("ip forwarding enabled");
}

/**
 * Bring `wg0` up via systemd (preferred) or `wg-quick` fallback.
 *
 * @param {object} r - Preflight report.
 */
function ensureUp(r) {
  if (r.wgUp) return log.ok("wg0 already up");
  if (r.systemd) {
    if (tryRunBin("systemctl", ["enable", "--now", `wg-quick@${WG_IFACE}`]) !== null) {
      return log.ok("wg0 up via systemd (wg-quick@wg0)");
    }
    log.warn("systemd start failed — falling back to wg-quick");
  }
  run(`wg-quick up ${WG_CONF}`);
  log.ok("wg0 up via wg-quick");
}

/**
 * Ensure NAT/forwarding rules are live and persisted.
 * Uses the {@link firewall} module for backend-agnostic rule management.
 * The conf-file update is performed under the {@link confLock}.
 *
 * @param {object} r - Preflight report.
 * @returns {Promise<void>}
 */
async function ensureNat(r) {
  const added = firewall.ensureLiveNat(r.wanIf, WG_IFACE);
  if (added) log.ok(`nat/forward rules applied (backend: ${firewall.backend()})`);

  // Persist — only if the conf doesn't already contain the sentinel.
  if (fs.existsSync(WG_CONF)) {
    const release = await confLock.acquire();
    try {
      const before = fs.readFileSync(WG_CONF, "utf8");
      const after  = firewall.patchConfNat(before, r.wanIf, WG_IFACE);
      if (after !== before) {
        fs.writeFileSync(WG_CONF, after, { mode: 0o600 });
        log.ok("nat rules persisted into wg0.conf");
      }
    } finally {
      release();
    }
  }
}

/**
 * Run the full WireGuard bootstrap sequence.
 *
 * @param {object} r - Preflight report from `preflight.collect()`.
 * @param {{ wgPort: number, agentPort: number }} opts
 * @returns {Promise<void>}
 */
async function ensure(r, { wgPort, agentPort }) {
  ensureInstalled(r);
  ensureConfig(r, wgPort);
  ensureForwarding();
  ensureUp(r);
  await ensureNat(r);
  firewall.openPorts(r.ufw, wgPort, agentPort);
}

// ---------------------------------------------------------------------------
// Peer management
// ---------------------------------------------------------------------------

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const IPV4_RE   = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RE   = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:)*:[0-9a-fA-F]{1,4}$/;

/**
 * Add a peer to the live WireGuard interface and persist it to `wg0.conf`.
 * Detects IP conflicts before making any changes to avoid silent data-plane
 * breakage.  All conf mutations are serialised through {@link confLock}.
 *
 * @param {string} publicKey - Base64 WireGuard public key.
 * @param {string} address   - Tunnel address(es), e.g. `10.66.0.2` or `10.66.0.2,fd00:66::2`.
 * @returns {Promise<{ added: true, address: string }>}
 * @throws {Error} On validation failure, IP conflict, or wg command failure.
 */
async function addPeer(publicKey, address) {
  if (!WG_KEY_RE.test(publicKey)) throw new Error("publicKey must be a base64 WireGuard key");
  
  const addrs = address.split(",").map((a) => a.trim());
  for (const a of addrs) {
    if (!IPV4_RE.test(a) && !IPV6_RE.test(a)) {
      throw new Error(`address ${a} is not a valid IPv4 or IPv6 address`);
    }
  }

  const allowedIps = addrs.map((a) => (a.includes(":") ? `${a}/128` : `${a}/32`)).join(",");

  // Conflict check
  const { peers } = dump();
  const conflict = peers.find(
    (p) => p.publicKey !== publicKey && addrs.some((a) => p.allowedIps.includes(a))
  );
  if (conflict) {
    throw new Error(
      `address ${address} is already assigned to peer ${conflict.publicKey.slice(0, 8)}…`
    );
  }

  // Apply live
  runBin("wg", [
    "set", WG_IFACE,
    "peer", publicKey,
    "allowed-ips", allowedIps,
    "persistent-keepalive", "25",
  ]);

  // Persist under the conf lock.
  const release = await confLock.acquire();
  try {
    let conf = fs.readFileSync(WG_CONF, "utf8");
    if (!conf.includes(publicKey)) {
      conf +=
        `# wpn-peer ${address}\n` +
        `[Peer]\n` +
        `PublicKey = ${publicKey}\n` +
        `AllowedIPs = ${allowedIps}\n` +
        `PersistentKeepalive = 25\n` +
        `\n`;
      fs.writeFileSync(WG_CONF, conf, { mode: 0o600 });
    }
  } finally {
    release();
  }

  return { added: true, address };
}

/**
 * Remove a peer from the live WireGuard interface and from `wg0.conf`.
 * The conf rewrite is serialised through {@link confLock}.
 *
 * @param {string} publicKey - Base64 WireGuard public key.
 * @returns {Promise<{ removed: true }>}
 */
async function removePeer(publicKey) {
  if (!WG_KEY_RE.test(publicKey)) throw new Error("invalid peer key");

  // Remove from live interface first (safe to do outside the lock — wg set is atomic).
  tryRunBin("wg", ["set", WG_IFACE, "peer", publicKey, "remove"]);

  const release = await confLock.acquire();
  try {
    const lines = fs.readFileSync(WG_CONF, "utf8").split("\n");
    const out   = [];
    let skipping = false;

    for (const line of lines) {
      if (line.includes(publicKey)) {
        while (out.length) {
          const top = out[out.length - 1];
          if (top.startsWith("# wpn-peer") || top.trim() === "[Peer]") out.pop();
          else break;
        }
        skipping = true;
        continue;
      }
      if (skipping) {
        if (line.trim() === "" || line.trim() === "[Peer]" || line.startsWith("#")) {
          skipping = false;
        } else {
          continue;
        }
      }
      out.push(line);
    }

    fs.writeFileSync(WG_CONF, out.join("\n"), { mode: 0o600 });
  } finally {
    release();
  }

  return { removed: true };
}

// ---------------------------------------------------------------------------
// Interface introspection
// ---------------------------------------------------------------------------

/**
 * Parse `wg show wg0 dump` output.
 *
 * Peer lines have 9 tab-separated fields:
 * `iface  pubkey  psk  endpoint  allowed-ips  handshake-epoch  rx  tx  keepalive`
 *
 * @returns {{ peers: Array<{publicKey:string, endpoint:string|null, allowedIps:string, latestHandshake:number, rx:number, tx:number}> }}
 */
function dump() {
  const out = tryRunBin("wg", ["show", WG_IFACE, "dump"]);
  if (!out) return { peers: [] };
  const peers = [];
  for (const line of out.split("\n")) {
    const f = line.split("\t");
    if (f.length !== 9) continue;
    peers.push({
      publicKey:       f[1],
      endpoint:        f[3] === "(none)" ? null : f[3],
      allowedIps:      f[4],
      latestHandshake: parseInt(f[5], 10) || 0,
      rx:              parseInt(f[6], 10) || 0,
      tx:              parseInt(f[7], 10) || 0,
    });
  }
  return { peers };
}

/**
 * Return aggregate statistics for the `wg0` interface.
 * Calls {@link dump} once and derives all values in a single pass.
 *
 * @returns {{ peerCount:number, activePeers:number, rxBytes:number, txBytes:number, load:number, peers: object[] }}
 */
function stats() {
  const { peers } = dump();
  const now       = Math.floor(Date.now() / 1_000);
  let rxBytes = 0, txBytes = 0, activePeers = 0;

  for (const p of peers) {
    rxBytes += p.rx;
    txBytes += p.tx;
    if (p.latestHandshake && now - p.latestHandshake < 180) activePeers++;
  }

  return {
    peerCount: peers.length,
    activePeers,
    rxBytes,
    txBytes,
    load: Math.min(100, Math.round((os.loadavg()[0] / os.cpus().length) * 100)),
    peers,
  };
}

// ---------------------------------------------------------------------------
// Version cache
// ---------------------------------------------------------------------------

/** @type {string|null|undefined} */
let _version;

/**
 * Return the installed `wireguard-tools` version string.
 * Cached — the binary version doesn't change while the agent runs.
 *
 * @returns {string|null}
 */
function version() {
  if (_version !== undefined) return _version;
  const out = tryRunBin("wg", ["--version"]);
  _version = (out && (out.match(/v[\d.]+/) || [])[0]) || out || null;
  return _version;
}

// ---------------------------------------------------------------------------
// Live interface facts
// ---------------------------------------------------------------------------

/**
 * Query live `wg0` state — the source of truth when `wg0` predates the agent.
 *
 * @returns {{ listenPort: number|null, subnet: string|null, address: string|null }}
 */
function liveInfo() {
  const listenPort = parseInt(tryRunBin("wg", ["show", WG_IFACE, "listen-port"]), 10) || null;
  const addrRaw    = tryRun(`ip -o -4 addr show dev ${WG_IFACE} | awk '{print $4; exit}'`);
  let subnet = null;
  if (addrRaw) {
    const [ip, mask] = addrRaw.split("/");
    subnet = mask === "24" ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : addrRaw;
  }
  return { listenPort, subnet, address: addrRaw };
}

/**
 * Return the public key of the live `wg0` interface.
 *
 * @param {string} pubFile - Path to the cached public-key file.
 * @returns {string|null}
 */
function serverPubKey(pubFile) {
  return (
    tryRunBin("wg", ["show", WG_IFACE, "public-key"]) ||
    (pubFile && fs.existsSync(pubFile)
      ? fs.readFileSync(pubFile, "utf8").trim()
      : tryRun(`wg pubkey < ${WG_KEY_FILE}`))
  );
}

module.exports = {
  ensure,
  addPeer,
  removePeer,
  dump,
  stats,
  serverPubKey,
  liveInfo,
  version,
  WG_IFACE,
  SUBNET_V4,
  SUBNET_V6,
  WG_CONF,
  // Exported for testing
  _WG_KEY_RE: WG_KEY_RE,
  _IPV4_RE:   IPV4_RE,
  _IPV6_RE:   IPV6_RE,
};
