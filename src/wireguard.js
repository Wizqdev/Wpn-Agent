/**
 * @fileoverview WireGuard lifecycle — install, `wg0` config, peer management,
 * stats, and interface introspection.
 *
 * All operations here require root; the agent enforces this at startup.
 *
 * Module-level imports of `os` are resolved once at load time rather than
 * inside hot-path functions.  The WireGuard version string is cached after the
 * first call to {@link version} since the binary doesn't change while the agent
 * is running.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const { run, tryRun, log } = require("./util");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WG_IFACE    = "wg0";
const WG_CONF     = "/etc/wireguard/wg0.conf";
const WG_KEY_FILE = "/etc/wireguard/server.key";
const SUBNET_GW   = "10.66.0.1/24";

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
    fs.writeFileSync(WG_KEY_FILE, run("wg genkey") + "\n", { mode: 0o600 });
    log.ok("server keypair generated");
  }

  if (!fs.existsSync(WG_CONF)) {
    const priv = fs.readFileSync(WG_KEY_FILE, "utf8").trim();
    const up   = `iptables -A FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -A FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${r.wanIf} -j MASQUERADE`;
    const down = `iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${r.wanIf} -j MASQUERADE`;
    fs.writeFileSync(
      WG_CONF,
      [
        "[Interface]",
        `Address = ${SUBNET_GW}`,
        `ListenPort = ${wgPort}`,
        `PrivateKey = ${priv}`,
        `PostUp = ${up}`,
        `PostDown = ${down}`,
        "",
      ].join("\n"),
      { mode: 0o600 }
    );
    log.ok(`wg0.conf written (nat on ${r.wanIf})`);
  }
}

/**
 * Enable IPv4/IPv6 forwarding and persist it via sysctl.d.
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
    if (tryRun(`systemctl enable --now wg-quick@${WG_IFACE}`) !== null) {
      return log.ok("wg0 up via systemd (wg-quick@wg0)");
    }
    log.warn("systemd start failed — falling back to wg-quick");
  }
  run(`wg-quick up ${WG_CONF}`);
  log.ok("wg0 up via wg-quick");
}

/**
 * Open the WireGuard and agent ports in ufw if it is available.
 *
 * @param {object} r - Preflight report.
 * @param {number} wgPort
 * @param {number} agentPort
 */
function ensureFirewall(r, wgPort, agentPort) {
  if (!r.ufw) return;
  tryRun(`ufw allow ${wgPort}/udp`);
  tryRun(`ufw allow ${agentPort}/tcp`);
  log.ok(`ufw: opened udp/${wgPort} + tcp/${agentPort}`);
}

/**
 * Ensure NAT/forwarding iptables rules are active and persisted into
 * `wg0.conf` (PostUp/PostDown), handling pre-existing WireGuard setups that
 * predate the agent.
 *
 * @param {object} r - Preflight report.
 */
function ensureNat(r) {
  const fwd    = `FORWARD -i ${WG_IFACE} -j ACCEPT`;
  const fwdOut = `FORWARD -o ${WG_IFACE} -j ACCEPT`;
  const nat    = `POSTROUTING -o ${r.wanIf} -j MASQUERADE`;

  const missing = [];
  for (const rule of [
    `iptables -C ${fwd}`,
    `iptables -C ${fwdOut}`,
    `iptables -t nat -C ${nat}`,
  ]) {
    if (tryRun(rule) === null) missing.push(rule.replace(" -C ", " -A "));
  }
  for (const add of missing) tryRun(add);
  if (missing.length) log.ok(`nat/forward rules added (${missing.length})`);

  // Persist into wg0.conf — only if MASQUERADE is not already there.
  if (fs.existsSync(WG_CONF) && !fs.readFileSync(WG_CONF, "utf8").includes("MASQUERADE")) {
    let conf      = fs.readFileSync(WG_CONF, "utf8");
    const upLine  = `iptables -A ${fwd}; iptables -A ${fwdOut}; iptables -t nat -A ${nat}`;
    const downLine = `iptables -D ${fwd}; iptables -D ${fwdOut}; iptables -t nat -D ${nat}`;
    if (/^PostUp\s*=/m.test(conf)) {
      conf = conf.replace(/^(PostUp\s*=.*)$/m, `$1; ${upLine}`);
      conf = /^PostDown\s*=/m.test(conf)
        ? conf.replace(/^(PostDown\s*=.*)$/m, `$1; ${downLine}`)
        : conf.replace(/^(PostUp\s*=.*)$/m, `$1\nPostDown = ${downLine}`);
    } else {
      conf = conf.replace(
        /^(PrivateKey\s*=.*)$/m,
        `$1\nPostUp = ${upLine}\nPostDown = ${downLine}`
      );
    }
    fs.writeFileSync(WG_CONF, conf, { mode: 0o600 });
    log.ok("nat rules persisted into wg0.conf");
  }
}

/**
 * Run the full WireGuard bootstrap sequence.
 *
 * @param {object} r - Preflight report from `preflight.collect()`.
 * @param {{ wgPort: number, agentPort: number }} opts
 */
function ensure(r, { wgPort, agentPort }) {
  ensureInstalled(r);
  ensureConfig(r, wgPort);
  ensureForwarding();
  ensureUp(r);
  ensureNat(r);
  ensureFirewall(r, wgPort, agentPort);
}

// ---------------------------------------------------------------------------
// Peer management
// ---------------------------------------------------------------------------

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const IPV4_RE   = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Add a peer to the live WireGuard interface and persist it to `wg0.conf`.
 *
 * @param {string} publicKey - Base64 WireGuard public key.
 * @param {string} address   - IPv4 tunnel address (e.g. `10.66.0.2`).
 * @returns {{ added: true, address: string }}
 */
function addPeer(publicKey, address) {
  if (!WG_KEY_RE.test(publicKey)) throw new Error("publicKey must be a base64 WireGuard key");
  if (!IPV4_RE.test(address))     throw new Error("address must be an IPv4 tunnel address");

  run(`wg set ${WG_IFACE} peer '${publicKey}' allowed-ips ${address}/32 persistent-keepalive 25`);

  let conf = fs.readFileSync(WG_CONF, "utf8");
  if (!conf.includes(publicKey)) {
    conf +=
      `# wpn-peer ${address}\n` +
      `[Peer]\n` +
      `PublicKey = ${publicKey}\n` +
      `AllowedIPs = ${address}/32\n` +
      `PersistentKeepalive = 25\n` +
      `\n`;
    fs.writeFileSync(WG_CONF, conf, { mode: 0o600 });
  }
  return { added: true, address };
}

/**
 * Remove a peer from the live WireGuard interface and from `wg0.conf`.
 *
 * @param {string} publicKey - Base64 WireGuard public key.
 * @returns {{ removed: true }}
 */
function removePeer(publicKey) {
  if (!WG_KEY_RE.test(publicKey)) throw new Error("invalid peer key");
  tryRun(`wg set ${WG_IFACE} peer '${publicKey}' remove`);

  const lines = fs.readFileSync(WG_CONF, "utf8").split("\n");
  const out   = [];
  let skipping = false;

  for (const line of lines) {
    if (line.includes(publicKey)) {
      // Drop the marker comment + [Peer] header already queued for this block.
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
        continue; // AllowedIPs / PersistentKeepalive of the removed peer
      }
    }
    out.push(line);
  }

  fs.writeFileSync(WG_CONF, out.join("\n"), { mode: 0o600 });
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
  const out = tryRun(`wg show ${WG_IFACE} dump`);
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
 * Calls {@link dump} once and derives all values from that single snapshot.
 *
 * @returns {{ peerCount:number, activePeers:number, rxBytes:number, txBytes:number, load:number, peers: object[] }}
 */
function stats() {
  const { peers } = dump();
  const now       = Math.floor(Date.now() / 1_000);
  let rxBytes = 0;
  let txBytes = 0;
  let activePeers = 0;

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
 * Return the installed `wireguard-tools` version string (e.g. `"v1.0.20210914"`).
 * Result is cached — the binary version doesn't change while the agent runs.
 *
 * @returns {string|null}
 */
function version() {
  if (_version !== undefined) return _version;
  const out = tryRun("wg --version");
  _version = (out && (out.match(/v[\d.]+/) || [])[0]) || out || null;
  return _version;
}

// ---------------------------------------------------------------------------
// Live interface facts
// ---------------------------------------------------------------------------

/**
 * Query live `wg0` state.  This is the source of truth when `wg0` predates
 * the agent.
 *
 * @returns {{ listenPort: number|null, subnet: string|null, address: string|null }}
 */
function liveInfo() {
  const listenPort = parseInt(tryRun(`wg show ${WG_IFACE} listen-port`), 10) || null;
  const addrRaw    = tryRun(`ip -o -4 addr show dev ${WG_IFACE} | awk '{print $4; exit}'`);
  let subnet = null;
  if (addrRaw) {
    const [ip, mask] = addrRaw.split("/");
    subnet = mask === "24" ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : addrRaw;
  }
  return { listenPort, subnet, address: addrRaw };
}

/**
 * Return the public key of the live `wg0` interface, preferring the runtime
 * value over the cached file (a pre-existing `wg0` may use a different key).
 *
 * @param {string} pubFile - Path to the cached public-key file.
 * @returns {string|null}
 */
function serverPubKey(pubFile) {
  return (
    tryRun(`wg show ${WG_IFACE} public-key`) ||
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
  LISTEN_GW: SUBNET_GW,
};
